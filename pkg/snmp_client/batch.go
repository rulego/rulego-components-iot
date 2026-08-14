package snmpclient

import (
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

// Batched GET for snmp points.
//
// gosnmp's Get accepts a slice of OIDs and packs them into a single PDU, but the
// original ReadPoints called it once per point with a one-element slice. A device
// exposing 50 OIDs therefore cost 50 UDP round trips instead of 2~3.
//
// Unlike modbus, OIDs need not be contiguous: any set fits one request, so there is
// no address sorting or hole tolerance here. The only limit is PDU size.

// maxOIDsPerGet caps OIDs per GET request.
//
// SNMP has no negotiated PDU limit; agents commonly accept ~1472 bytes (Ethernet MTU
// minus headers), which fits roughly 30~40 typical OIDs. 24 leaves headroom for long
// OIDs and v3 auth overhead. Oversized requests get tooBig or a silent drop, and the
// per-chunk fallback below turns either into per-point reads rather than data loss.
const maxOIDsPerGet = 24

// snmpGetter is the single method the batched read needs. *gosnmp.GoSNMP satisfies it.
//
// Declared so tests can drive chunking, OID matching, ordering and the fallback path
// without a live agent — those are exactly the branches where mis-assigned values would
// hide, and gosnmp offers no in-process server to test against.
type snmpGetter interface {
	Get(oids []string) (*gosnmp.SnmpPacket, error)
}

// readGetBatch reads get-mode points in batches, writing each result to out[i] for
// point i. Points are matched by OID rather than by response position: agents may
// reorder or omit variables, and matching by index would silently mis-assign values
// to the wrong point name.
//
// A whole-chunk failure falls back to per-point reads so one bad OID cannot lose the
// rest of the chunk (same rationale as the modbus block fallback).
func readGetBatch(client snmpGetter, idx []int, points []Point, out [][]Data, logger types.Logger) (failCount int, lastErr error) {
	for start := 0; start < len(idx); start += maxOIDsPerGet {
		end := start + maxOIDsPerGet
		if end > len(idx) {
			end = len(idx)
		}
		chunk := idx[start:end]

		oids := make([]string, 0, len(chunk))
		for _, i := range chunk {
			oids = append(oids, points[i].OID)
		}

		resp, err := client.Get(oids)
		if err != nil || resp == nil {
			// A timeout means the agent is silent; per-point reads and later
			// chunks would each wait another full window for the same silence.
			if iot_points.IsTimeoutErr(err) {
				if logger != nil {
					logger.Warnf("[SNMP] batch get of %d oids timed out, skipping per-point fallback: %v", len(oids), err)
				}
				for _, i := range idx[start:] {
					out[i] = []Data{{Name: points[i].Name, Address: points[i].OID, Quality: "bad", Timestamp: time.Now()}}
					failCount++
				}
				return failCount, err
			}
			// Connection hiccup or oversized PDU: retry this chunk point by point.
			if logger != nil {
				logger.Warnf("[SNMP] batch get of %d oids failed, falling back to per-point: %v", len(oids), err)
			}
			for _, i := range chunk {
				d, perErr := readGet(client, points[i])
				if perErr != nil {
					d.Quality = "bad"
					failCount++
					lastErr = perErr
					if logger != nil {
						logger.Errorf("[SNMP] get %s error: %v", points[i].OID, perErr)
					}
				}
				out[i] = []Data{d}
			}
			continue
		}

		byOID := make(map[string]gosnmp.SnmpPDU, len(resp.Variables))
		for _, v := range resp.Variables {
			byOID[normalizeOID(v.Name)] = v
		}
		for _, i := range chunk {
			pdu, ok := byOID[normalizeOID(points[i].OID)]
			if !ok {
				// Agent omitted this OID: mark the point bad instead of leaving a hole.
				out[i] = []Data{{Name: points[i].Name, Address: points[i].OID, Quality: "bad", Timestamp: time.Now()}}
				failCount++
				if logger != nil {
					logger.Errorf("[SNMP] oid %s missing from batch response", points[i].OID)
				}
				continue
			}
			d := pduToData(points[i].Name, pdu)
			if d.Quality == "bad" {
				failCount++
			}
			out[i] = []Data{d}
		}
	}
	return failCount, lastErr
}

// normalizeOID strips the leading dot so request and response forms compare equal
// (agents return ".1.3.6..." while configs usually omit the dot).
func normalizeOID(oid string) string {
	return strings.TrimPrefix(strings.TrimSpace(oid), ".")
}
