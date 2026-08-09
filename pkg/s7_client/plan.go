package s7client

import (
	"sort"
	"strings"
)

// Batched range reads for s7 points.
//
// ReadPoints used to issue one AGReadXX per point. A DB with 40 tags therefore cost
// 40 round trips; on a busy PLC that alone exceeds a 1s poll cycle.
//
// Same shape as the modbus merge: group by area (DB also by number), sort by byte
// offset, merge neighbours into one range read, then slice the buffer per point.
// Decoding needs no change because decodeScalar/decodeArray already take a []byte.

const (
	// s7ReplyHeader is what gos7 subtracts from the negotiated PDU length to get the
	// usable payload (client.go: maxElements = (PDULength - 18) / wordSize).
	s7ReplyHeader = 18
	// s7FallbackPDU is used when the handler has not negotiated yet (PDULength <= 0).
	// 240 is the common S7-300/400 default; being conservative only costs an extra request.
	s7FallbackPDU = 240
	// s7MergeGap is how many unused bytes may sit between two points and still merge.
	// Reading a few spare bytes is far cheaper than a second round trip.
	s7MergeGap = 16
)

// readPlan is one point's placement inside a range read.
type readPlan struct {
	index int   // position in the caller's points slice
	point Point //
	start int   // byte offset of this point
	width int   // bytes this point occupies
}

// pointWidth returns how many bytes a point occupies, ok=false when the type is unknown.
//
// BOOL is one byte on purpose: several BOOLs sharing a byte differ only by BitOffset,
// so one byte read covers all of them and decodeScalar picks the bit.
func pointWidth(p Point) (int, bool) {
	t := strings.ToUpper(strings.TrimSpace(p.Type))
	ts := sizeOfType(t)
	if ts == 0 {
		return 0, false
	}
	if t == "STRING" {
		return stringMaxLen(p) + 2, true
	}
	count := p.Count
	if count <= 0 {
		count = 1
	}
	return ts * count, true
}

// planKey groups points that may share one request: same area, and for DB the same
// block number. Points from different areas can never be merged.
func planKey(p Point) (string, error) {
	area, err := parseArea(p.Area)
	if err != nil {
		return "", err
	}
	if area == areaDB {
		// DB blocks are independent address spaces; only same-block points may merge.
		return "DB/" + itoa(p.DbNumber), nil
	}
	// M/I/Q each form one space, keyed by the protocol area id.
	return "A/" + itoa(area), nil
}

// planGroups buckets points by planKey. Points with a bad area or unknown type are
// returned in bad so the caller can mark them without attempting a read.
func planGroups(points []Point) (groups map[string][]readPlan, keys []string, bad []int) {
	groups = make(map[string][]readPlan)
	for i, p := range points {
		key, err := planKey(p)
		if err != nil {
			bad = append(bad, i)
			continue
		}
		w, ok := pointWidth(p)
		if !ok {
			bad = append(bad, i)
			continue
		}
		if _, seen := groups[key]; !seen {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], readPlan{index: i, point: p, start: p.Address, width: w})
	}
	// Stable key order keeps request sequence deterministic across runs.
	sort.Strings(keys)
	return groups, keys, bad
}

// chunkPlans splits an offset-sorted group into blocks that each fit one PDU.
// maxBytes is the usable payload; a single point wider than that gets its own block
// and is left to the per-point path (which is what the old code always did).
func chunkPlans(g []readPlan, maxBytes int) [][]readPlan {
	if len(g) == 0 {
		return nil
	}
	if maxBytes < 1 {
		maxBytes = 1
	}
	var blocks [][]readPlan
	cur := []readPlan{g[0]}
	start := g[0].start
	end := g[0].start + g[0].width
	for _, p := range g[1:] {
		newEnd := end
		if p.start+p.width > newEnd {
			newEnd = p.start + p.width
		}
		if p.start > end+s7MergeGap || newEnd-start > maxBytes {
			blocks = append(blocks, cur)
			cur = []readPlan{p}
			start = p.start
			end = p.start + p.width
			continue
		}
		cur = append(cur, p)
		end = newEnd
	}
	return append(blocks, cur)
}

// usablePayload turns a negotiated PDU length into the byte budget for one range read.
func usablePayload(pduLength int) int {
	if pduLength <= 0 {
		pduLength = s7FallbackPDU
	}
	n := pduLength - s7ReplyHeader
	if n < 1 {
		n = 1
	}
	return n
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
