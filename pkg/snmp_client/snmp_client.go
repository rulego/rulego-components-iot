/*
 * Copyright 2026 The RuleGo Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package snmpclient wraps gosnmp/gosnmp, providing SNMP (v1/v2c/v3) connections,
// bulk OID read (Get/Walk), write (Set), and PDU type parsing.
// Outputs unified Data contract for downstream rulego nodes.

package snmpclient

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

// SnmpDataMsgType is the SNMP data message type.
const SnmpDataMsgType = "SNMP_DATA"

// Data is the unified point output contract.
type Data struct {
	Name      string      `json:"name"`
	Address   string      `json:"address"` // OID
	Value     interface{} `json:"value"`
	Type      string      `json:"type"` // SNMP type string
	Quality   string      `json:"quality"`
	Timestamp time.Time   `json:"timestamp"`
}

// Point SNMP point definition, shared for read/write
type Point struct {
	Name  string `json:"name"`            // Point name
	OID   string `json:"oid"`             // OID, e.g. 1.3.6.1.2.1.1.5.0
	Op    string `json:"op,omitempty"`    // Read operation: get(default)/walk; ignored for write
	Type  string `json:"type,omitempty"`  // Write only: value type (Integer/OctetString/...)
	Value string `json:"value,omitempty"` // Write only: string representation of value
}

// ConfigProp SNMP connection configuration interface
type ConfigProp interface {
	GetServer() string        // host or host:port, default port 161
	GetVersion() string       // v1/v2c/v3
	GetCommunity() string     // v1/v2c community
	GetTimeout() int          // seconds
	GetSecurityLevel() string // v3: noAuthNoPriv/authNoPriv/authPriv
	GetUsername() string      // v3
	GetAuthProtocol() string  // v3: None/MD5/SHA/SHA224/SHA256/SHA384/SHA512
	GetAuthPassword() string  // v3
	GetPrivProtocol() string  // v3: None/DES/AES/AES192/AES256
	GetPrivPassword() string  // v3
}

// Holder SNMP client configuration holder
type Holder struct {
	Config ConfigProp
}

// DefaultHolder default configuration
func DefaultHolder(c ConfigProp) *Holder {
	return &Holder{Config: c}
}

// NewClient creates and connects an SNMP client.
func (h *Holder) NewClient() (*gosnmp.GoSNMP, error) {
	if h.Config == nil {
		return nil, errors.New("snmp config is nil")
	}
	target, port, err := iot_points.ParseServer(h.Config.GetServer(), 161)
	if err != nil {
		return nil, err
	}
	timeout := h.Config.GetTimeout()
	if timeout <= 0 {
		timeout = iot_points.DefaultTimeoutSec
	}
	version, err := parseVersion(h.Config.GetVersion())
	if err != nil {
		return nil, err
	}
	// Retries stays at 1: each retry waits a full Timeout, which multiplies with
	// the node-layer reconnect rounds into minutes against a silent agent.
	g := &gosnmp.GoSNMP{
		Target:    target,
		Port:      uint16(port),
		Community: h.Config.GetCommunity(),
		Version:   version,
		Timeout:   time.Duration(timeout) * time.Second,
		Retries:   1,
		MaxOids:   60,
	}
	if version == gosnmp.Version3 {
		if err := applyV3(g, h.Config); err != nil {
			return nil, err
		}
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return g, nil
}

// parseVersion version string -> gosnmp.SnmpVersion
func parseVersion(s string) (gosnmp.SnmpVersion, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "v2c", "v2", "2c":
		return gosnmp.Version2c, nil
	case "v1", "1":
		return gosnmp.Version1, nil
	case "v3", "3":
		return gosnmp.Version3, nil
	}
	return 0, fmt.Errorf("unsupported snmp version: %q", s)
}

// applyV3 configures SNMPv3 USM security parameters
func applyV3(g *gosnmp.GoSNMP, c ConfigProp) error {
	level, err := parseSecurityLevel(c.GetSecurityLevel())
	if err != nil {
		return err
	}
	g.MsgFlags = level
	g.SecurityParameters = &gosnmp.UsmSecurityParameters{
		UserName:                 c.GetUsername(),
		AuthenticationPassphrase: c.GetAuthPassword(),
		PrivacyPassphrase:        c.GetPrivPassword(),
		AuthenticationProtocol:   parseAuthProtocol(c.GetAuthProtocol()),
		PrivacyProtocol:          parsePrivProtocol(c.GetPrivProtocol()),
	}
	return nil
}

func parseSecurityLevel(s string) (gosnmp.SnmpV3MsgFlags, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "noauthnopriv":
		return gosnmp.NoAuthNoPriv, nil
	case "authnopriv":
		return gosnmp.AuthNoPriv, nil
	case "authpriv":
		return gosnmp.AuthPriv, nil
	}
	return 0, fmt.Errorf("unsupported snmpv3 security level: %q", s)
}

func parseAuthProtocol(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "NONE":
		return gosnmp.NoAuth
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	}
	return gosnmp.NoAuth
}

func parsePrivProtocol(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "NONE":
		return gosnmp.NoPriv
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	}
	return gosnmp.NoPriv
}

// ReadPoints batch reads OIDs. op=get reads single value precisely, op=walk traverses subtree returning multiple values.
// Single point failure does not affect others (marked quality=bad).
func ReadPoints(client *gosnmp.GoSNMP, points []Point, logger types.Logger) ([]Data, error) {
	if client == nil {
		return nil, errors.New("snmp client is nil")
	}
	// Per-point slots keep output ordered by point index even though get points are
	// read out of order in batches, and walk points expand to several Data each.
	perPoint := make([][]Data, len(points))

	// Walk points stay one request each: a subtree traversal cannot be packed with others.
	// Get points are collected and batched below.
	getIdx, failCount, lastErr, timedOut := walkPoints(client, points, perPoint, logger)
	if !timedOut && len(getIdx) > 0 {
		n, err := readGetBatch(client, getIdx, points, perPoint, logger)
		failCount += n
		if err != nil {
			lastErr = err
		}
	}

	results := make([]Data, 0, len(points))
	for _, ds := range perPoint {
		results = append(results, ds...)
	}
	// All points failed: suspected connection-level error, return error
	if len(points) > 0 && failCount == len(points) {
		return results, fmt.Errorf("all %d points failed (possible connection error): %w", failCount, lastErr)
	}
	return results, nil
}

// oidWalker is the walk subset *gosnmp.GoSNMP provides; an interface so the
// walk timeout path is testable without a live agent.
type oidWalker interface {
	Walk(rootOid string, fn gosnmp.WalkFunc) error
}

// walkPoints walks op=walk points one request each and collects get-mode indexes
// for batching. A walk timeout means the agent is silent: the remaining points
// (walk and get alike) are marked bad and nothing is collected for the batch,
// instead of waiting one more window per point.
func walkPoints(client oidWalker, points []Point, perPoint [][]Data, logger types.Logger) (getIdx []int, failCount int, lastErr error, timedOut bool) {
	for i, p := range points {
		if timedOut {
			perPoint[i] = []Data{{Name: p.Name, Address: p.OID, Quality: "bad", Timestamp: time.Now()}}
			failCount++
			continue
		}
		if strings.ToLower(strings.TrimSpace(p.Op)) != "walk" {
			getIdx = append(getIdx, i)
			continue
		}
		ds, err := readWalk(client, p)
		if err != nil {
			perPoint[i] = []Data{{Name: p.Name, Address: p.OID, Quality: "bad", Type: "walk", Timestamp: time.Now()}}
			failCount++
			lastErr = err
			if logger != nil {
				logger.Errorf("[SNMP] walk %s error: %v", p.OID, err)
			}
			timedOut = iot_points.IsTimeoutErr(err)
			continue
		}
		perPoint[i] = ds
	}
	return getIdx, failCount, lastErr, timedOut
}

// readGet precisely reads single OID
func readGet(client snmpGetter, p Point) (Data, error) {
	if strings.TrimSpace(p.OID) == "" {
		return Data{Name: p.Name, Address: p.OID, Quality: "bad", Timestamp: time.Now()}, errors.New("empty OID")
	}
	resp, err := client.Get([]string{p.OID})
	if err != nil {
		return Data{Name: p.Name, Address: p.OID, Timestamp: time.Now()}, err
	}
	if len(resp.Variables) == 0 {
		return Data{Name: p.Name, Address: p.OID, Timestamp: time.Now()}, errors.New("no variable returned")
	}
	return pduToData(p.Name, resp.Variables[0]), nil
}

// maxWalkResults caps Data entries per walk point. A mis-scoped root (e.g.
// "walk:1") can span tens of thousands of OIDs; the cap fails the point loudly
// instead of flooding msg.Data and holding the op lock for minutes.
const maxWalkResults = 2000

// errWalkTooLarge aborts the walk callback once the result cap is reached.
var errWalkTooLarge = errors.New("walk result cap exceeded")

// readWalk traverses OID subtree. Returns ErrNoWalkResults when the root does not exist or yields
// no leaves, so the caller can mark the point bad instead of silently dropping it.
func readWalk(client oidWalker, p Point) ([]Data, error) {
	if strings.TrimSpace(p.OID) == "" {
		return nil, errors.New("empty OID")
	}
	out := make([]Data, 0)
	err := client.Walk(p.OID, func(d gosnmp.SnmpPDU) error {
		if len(out) >= maxWalkResults {
			return errWalkTooLarge
		}
		out = append(out, pduToData(p.Name, d))
		return nil
	})
	if errors.Is(err, errWalkTooLarge) {
		return out, fmt.Errorf("walk %s exceeded cap of %d oids; narrow the subtree", p.OID, maxWalkResults)
	}
	if err != nil {
		return out, err
	}
	if len(out) == 0 {
		return out, ErrNoWalkResults
	}
	return out, nil
}

// ErrNoWalkResults indicates a Walk completed without error but yielded no OIDs (root not found).
var ErrNoWalkResults = errors.New("walk returned no results")

// pduToData converts gosnmp PDU to unified Data.
// OctetString/Opaque arrive as []byte (gosnmp decodes them that way); convert to string so JSON
// serialization does not base64-encode them. NoSuchObject/NoSuchInstance/EndOfMibView (returned
// for non-existent OIDs) and nil values are marked quality=bad, not reported as good-with-null.
func pduToData(name string, pdu gosnmp.SnmpPDU) Data {
	d := Data{
		Name:      name,
		Address:   pdu.Name,
		Type:      pduTypeString(pdu.Type),
		Timestamp: time.Now(),
	}
	switch pdu.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		d.Quality = "bad"
		return d
	}
	switch val := pdu.Value.(type) {
	case []byte:
		// OctetString / Opaque / BitString decode to []byte; expose as string for JSON output.
		d.Value = string(val)
		d.Quality = "good"
	case nil:
		d.Quality = "bad"
	default:
		d.Value = val
		d.Quality = "good"
	}
	return d
}

// pduTypeString PDU type constant -> readable string
func pduTypeString(t gosnmp.Asn1BER) string {
	switch t {
	case gosnmp.Integer:
		return "Integer"
	case gosnmp.OctetString:
		return "OctetString"
	case gosnmp.ObjectIdentifier:
		return "ObjectIdentifier"
	case gosnmp.IPAddress:
		return "IPAddress"
	case gosnmp.Counter32:
		return "Counter32"
	case gosnmp.Gauge32:
		return "Gauge32"
	case gosnmp.TimeTicks:
		return "TimeTicks"
	case gosnmp.Counter64:
		return "Counter64"
	case gosnmp.Null:
		return "Null"
	case gosnmp.NoSuchObject:
		return "NoSuchObject"
	case gosnmp.NoSuchInstance:
		return "NoSuchInstance"
	case gosnmp.EndOfMibView:
		return "EndOfMibView"
	}
	return fmt.Sprintf("Asn1BER(%d)", int(t))
}

// WritePoints batch writes OIDs (Set). Returns error immediately on any failure
func WritePoints(client *gosnmp.GoSNMP, points []Point) error {
	if client == nil {
		return errors.New("snmp client is nil")
	}
	for _, p := range points {
		val, asnType, err := encodeValue(p.Value, p.Type)
		if err != nil {
			return fmt.Errorf("encode %s error: %w", p.OID, err)
		}
		pdus := []gosnmp.SnmpPDU{{Name: p.OID, Type: asnType, Value: val}}
		resp, err := client.Set(pdus)
		if err != nil {
			return fmt.Errorf("set %s error: %w", p.OID, err)
		}
		// gosnmp returns a nil error even when the agent refuses the write with a non-NoError
		// status (notWritable, wrongValue, inconsistentName, ...). Inspect the response so a
		// rejected Set is not silently reported as success.
		if resp == nil || resp.Error != gosnmp.NoError {
			status := "<nil response>"
			if resp != nil {
				status = resp.Error.String()
			}
			return fmt.Errorf("set %s failed: %s", p.OID, status)
		}
	}
	return nil
}

// encodeValue parses value string by type into Go value + Asn1BER (for Set).
// Go value types must match what gosnmp's marshalVarbind accepts for each ASN.1 type:
// Counter32/Gauge32/TimeTicks require uint32, Counter64 requires uint64 (a Go int/int64 is rejected).
func encodeValue(value, typ string) (interface{}, gosnmp.Asn1BER, error) {
	v := strings.TrimSpace(value)
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "integer", "int":
		n, err := parseInt(v)
		return n, gosnmp.Integer, err
	case "octetstring", "string":
		return v, gosnmp.OctetString, nil
	case "objectidentifier", "oid":
		return v, gosnmp.ObjectIdentifier, nil
	case "ipaddress", "ip":
		return v, gosnmp.IPAddress, nil
	case "counter32":
		n, err := parseUint32(v)
		return n, gosnmp.Counter32, err
	case "gauge32", "uint32":
		n, err := parseUint32(v)
		return n, gosnmp.Gauge32, err
	case "timeticks":
		n, err := parseUint32(v)
		return n, gosnmp.TimeTicks, err
	case "counter64":
		n, err := parseUint64(v)
		return n, gosnmp.Counter64, err
	}
	return nil, 0, fmt.Errorf("unsupported snmp type: %q", typ)
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func parseUint32(s string) (uint32, error) {
	var n uint32
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func parseUint64(s string) (uint64, error) {
	var n uint64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
