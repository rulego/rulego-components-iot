package s7client

import (
	"errors"
	"strings"
	"time"

	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
)

// errUnsupportedArea guards readArea's default branch. parseArea already rejects
// unknown areas, so reaching this means an area id was added without a read path.
var errUnsupportedArea = errors.New("s7: unsupported area id")

// s7Reader is the subset of gos7.Client the batched read needs.
//
// Declared so tests can drive block reads, buffer slicing and the fallback path
// without a PLC: gos7 ships no in-process server, and these are exactly the branches
// where a wrong offset would silently hand a point its neighbour's bytes.
type s7Reader interface {
	AGReadDB(dbNumber int, start int, size int, buffer []byte) error
	AGReadMB(start int, size int, buffer []byte) error
	AGReadEB(start int, size int, buffer []byte) error
	AGReadAB(start int, size int, buffer []byte) error
}

// readArea dispatches a range read to the right area function.
func readArea(client s7Reader, area int, dbNumber, start, size int, buf []byte) error {
	switch area {
	case areaDB:
		return client.AGReadDB(dbNumber, start, size, buf)
	case areaM:
		return client.AGReadMB(start, size, buf)
	case areaI:
		return client.AGReadEB(start, size, buf)
	case areaQ:
		return client.AGReadAB(start, size, buf)
	}
	return errUnsupportedArea
}

// readBlocks reads every planned block and fills out[i] for each point.
//
// A block read failure degrades to per-point reads for that block only, so one
// unreadable address cannot lose its neighbours (a PLC may refuse a range that
// crosses into a protected offset while the individual tags are readable).
func readBlocks(client s7Reader, points []Point, out []Data, pduLength int, logger types.Logger) (failCount int, lastErr error) {
	groups, keys, bad := planGroups(points)

	// Unparseable area or unknown type: never attempted, marked here.
	for _, i := range bad {
		out[i] = badData(points[i], "unsupported area or type")
		failCount++
	}

	maxBytes := usablePayload(pduLength)
	for _, k := range keys {
		g := groups[k]
		sortByStart(g)
		for _, blk := range chunkPlans(g, maxBytes) {
			n, err := readBlock(client, blk, out, logger)
			failCount += n
			if err != nil {
				lastErr = err
			}
		}
	}
	return failCount, lastErr
}

// readBlock reads one contiguous span and slices it per point.
func readBlock(client s7Reader, blk []readPlan, out []Data, logger types.Logger) (failCount int, lastErr error) {
	if len(blk) == 1 {
		return readSingle(client, blk[0], out, logger)
	}
	area, err := parseArea(blk[0].point.Area)
	if err != nil {
		return readEachInBlock(client, blk, out, logger)
	}
	start := blk[0].start
	end := start
	for _, p := range blk {
		if e := p.start + p.width; e > end {
			end = e
		}
	}
	buf := make([]byte, end-start)
	if err := readArea(client, area, blk[0].point.DbNumber, start, len(buf), buf); err != nil {
		// Timeout means the PLC is unreachable; per-point reads would each wait
		// another full window for the same silence.
		if iot_points.IsTimeoutErr(err) {
			for _, p := range blk {
				out[p.index] = badData(p.point, err.Error())
				failCount++
			}
			return failCount, err
		}
		if logger != nil {
			logger.Warnf("[S7] block read %s[%d..%d] failed, falling back to per-point: %v",
				blk[0].point.Area, start, end, err)
		}
		return readEachInBlock(client, blk, out, logger)
	}
	for _, p := range blk {
		off := p.start - start
		if off < 0 || off+p.width > len(buf) {
			// Should not happen; guard rather than slice out of range.
			out[p.index] = badData(p.point, "block offset out of range")
			failCount++
			continue
		}
		val, derr := decodeFromBuf(p.point, buf[off:off+p.width])
		if derr != nil {
			out[p.index] = badData(p.point, derr.Error())
			failCount++
			lastErr = derr
			continue
		}
		out[p.index] = goodData(p.point, val)
	}
	return failCount, lastErr
}

// readEachInBlock retries a failed block point by point.
func readEachInBlock(client s7Reader, blk []readPlan, out []Data, logger types.Logger) (failCount int, lastErr error) {
	for i, p := range blk {
		n, err := readSingle(client, p, out, logger)
		failCount += n
		if err != nil {
			lastErr = err
			// Timeout: mark the rest failed instead of waiting one more
			// window per point.
			if iot_points.IsTimeoutErr(err) {
				for _, rest := range blk[i+1:] {
					out[rest.index] = badData(rest.point, err.Error())
					failCount++
				}
				break
			}
		}
	}
	return failCount, lastErr
}

// readSingle reads one point on its own (also the path for oversized points).
func readSingle(client s7Reader, p readPlan, out []Data, logger types.Logger) (int, error) {
	area, err := parseArea(p.point.Area)
	if err != nil {
		out[p.index] = badData(p.point, err.Error())
		return 1, err
	}
	buf := make([]byte, p.width)
	if err := readArea(client, area, p.point.DbNumber, p.start, len(buf), buf); err != nil {
		if logger != nil {
			logger.Errorf("[S7] read %s error: %v", formatAddr(p.point), err)
		}
		out[p.index] = badData(p.point, err.Error())
		return 1, err
	}
	val, derr := decodeFromBuf(p.point, buf)
	if derr != nil {
		out[p.index] = badData(p.point, derr.Error())
		return 1, derr
	}
	out[p.index] = goodData(p.point, val)
	return 0, nil
}

// decodeFromBuf decodes a point's bytes; mirrors the tail of the old readPoint.
func decodeFromBuf(p Point, buf []byte) (interface{}, error) {
	t := strings.ToUpper(strings.TrimSpace(p.Type))
	count := p.Count
	if count <= 0 {
		count = 1
	}
	if count > 1 && t != "BOOL" && t != "STRING" {
		return decodeArray(buf, t, count)
	}
	return decodeScalar(buf, t, p.BitOffset)
}

// sortByStart orders a group by byte offset (insertion sort: groups are small and
// this keeps equal offsets in input order, which matters for several BOOLs in one byte).
func sortByStart(g []readPlan) {
	for i := 1; i < len(g); i++ {
		for j := i; j > 0 && g[j].start < g[j-1].start; j-- {
			g[j], g[j-1] = g[j-1], g[j]
		}
	}
}

func goodData(p Point, val interface{}) Data {
	return Data{
		Name:      p.Name,
		Address:   formatAddr(p),
		Type:      strings.ToUpper(strings.TrimSpace(p.Type)),
		Value:     val,
		Quality:   "good",
		Timestamp: time.Now(),
	}
}

func badData(p Point, _ string) Data {
	return Data{
		Name:      p.Name,
		Address:   formatAddr(p),
		Type:      strings.ToUpper(strings.TrimSpace(p.Type)),
		Quality:   "bad",
		Timestamp: time.Now(),
	}
}
