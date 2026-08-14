package snmpclient

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/stretchr/testify/assert"
)

// fakeAgent counts Get calls and answers from a fixed OID table, so batching,
// OID matching, ordering and the fallback path are all testable without a live agent.
type fakeAgent struct {
	values map[string]interface{} // normalized OID -> value
	calls  int                    // Get invocations
	sizes  []int                  // OIDs per invocation
	// failWhenLargerThan makes Get fail for multi-OID requests, simulating an agent
	// that rejects big PDUs (tooBig) so the per-point fallback can be exercised.
	failWhenLargerThan int
	// timeoutErr, when set, makes every Get fail with this timeout-class error —
	// simulating an agent that never answers at all.
	timeoutErr error
	// omit lists OIDs the agent silently drops from the response.
	omit map[string]bool
	// reorder returns variables in reverse request order (agents are not required
	// to preserve order; matching by index would silently mis-assign values).
	reorder bool
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{values: map[string]interface{}{}, omit: map[string]bool{}, failWhenLargerThan: 0}
}

func (f *fakeAgent) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	f.calls++
	f.sizes = append(f.sizes, len(oids))
	if f.timeoutErr != nil {
		return nil, f.timeoutErr
	}
	if f.failWhenLargerThan > 0 && len(oids) > f.failWhenLargerThan {
		return nil, errors.New("tooBig")
	}
	vars := make([]gosnmp.SnmpPDU, 0, len(oids))
	for _, o := range oids {
		n := normalizeOID(o)
		if f.omit[n] {
			continue
		}
		v, ok := f.values[n]
		if !ok {
			vars = append(vars, gosnmp.SnmpPDU{Name: "." + n, Type: gosnmp.NoSuchObject})
			continue
		}
		vars = append(vars, gosnmp.SnmpPDU{Name: "." + n, Type: gosnmp.Integer, Value: v})
	}
	if f.reorder {
		for i, j := 0, len(vars)-1; i < j; i, j = i+1, j-1 {
			vars[i], vars[j] = vars[j], vars[i]
		}
	}
	return &gosnmp.SnmpPacket{Variables: vars}, nil
}

// getPoints builds n get-mode points with distinct OIDs and values.
func getPoints(n int) ([]Point, *fakeAgent) {
	f := newFakeAgent()
	pts := make([]Point, 0, n)
	for i := 0; i < n; i++ {
		oid := fmt.Sprintf("1.3.6.1.2.1.99.%d", i)
		f.values[oid] = i * 10
		pts = append(pts, Point{Name: fmt.Sprintf("p%d", i), OID: oid})
	}
	return pts, f
}

// runBatch drives readGetBatch over all points and flattens the per-point slots.
func runBatch(client snmpGetter, pts []Point) ([]Data, int) {
	idx := make([]int, len(pts))
	for i := range pts {
		idx[i] = i
	}
	out := make([][]Data, len(pts))
	fail, _ := readGetBatch(client, idx, pts, out, nil)
	var flat []Data
	for _, ds := range out {
		flat = append(flat, ds...)
	}
	return flat, fail
}

// 50 个 OID 应打包成 3 次请求(24+24+2),而非 50 次。
func TestReadGetBatch_ReducesRequests(t *testing.T) {
	pts, f := getPoints(50)
	data, fail := runBatch(f, pts)

	assert.Equal(t, 50, len(data))
	assert.Equal(t, 0, fail)
	assert.Equal(t, 3, f.calls, "50 个 OID 应分 3 批(上限 %d),而非逐点 50 次", maxOIDsPerGet)
	assert.Equal(t, []int{24, 24, 2}, f.sizes)
}

// 结果顺序必须与点位顺序一致,且值对得上名字。
func TestReadGetBatch_PreservesOrder(t *testing.T) {
	pts, f := getPoints(30)
	data, _ := runBatch(f, pts)

	assert.Equal(t, 30, len(data))
	for i := range pts {
		assert.Equal(t, pts[i].Name, data[i].Name, "第 %d 条名字错位", i)
		assert.Equal(t, i*10, data[i].Value, "点位 %s 值错位", pts[i].Name)
	}
}

// agent 乱序返回时,必须按 OID 匹配而不是按下标 —— 否则值会静默配到错的点位名上。
func TestReadGetBatch_MatchesByOIDNotIndex(t *testing.T) {
	pts, f := getPoints(10)
	f.reorder = true
	data, fail := runBatch(f, pts)

	assert.Equal(t, 0, fail)
	for i := range pts {
		assert.Equal(t, pts[i].Name, data[i].Name)
		assert.Equal(t, i*10, data[i].Value, "乱序响应下点位 %s 的值被错配", pts[i].Name)
	}
}

// 整批失败必须回退逐点读,不能丢掉整批数据。
func TestReadGetBatch_FallsBackPerPoint(t *testing.T) {
	pts, f := getPoints(5)
	f.failWhenLargerThan = 1 // 多 OID 请求一律失败,单 OID 放行
	data, fail := runBatch(f, pts)

	assert.Equal(t, 5, len(data))
	assert.Equal(t, 0, fail, "回退到逐点后应全部成功")
	// 1 次失败的批 + 5 次逐点 = 6
	assert.Equal(t, 6, f.calls)
	for i := range pts {
		assert.Equal(t, i*10, data[i].Value)
	}
}

// 批量请求超时(agent 全程不应答)时必须跳过逐点兜底:逐点只会对着同样的沉默
// 再各等一个完整超时窗口。整批标 bad,只发一次请求;多 chunk 时后续 chunk 也不再发。
func TestReadGetBatch_TimeoutSkipsPerPointFallback(t *testing.T) {
	pts, f := getPoints(30) // 30 > maxOIDsPerGet, 会切成两个 chunk
	f.timeoutErr = errors.New("request timeout (after 0 retries)")
	data, fail := runBatch(f, pts)

	assert.Equal(t, 30, len(data))
	assert.Equal(t, 30, fail)
	assert.Equal(t, 1, f.calls, "超时应跳过逐点兜底和后续 chunk,只发一次批量请求")
	for i := range pts {
		assert.Equal(t, "bad", data[i].Quality)
		assert.Equal(t, pts[i].Name, data[i].Name, "超时标 bad 时槽位仍须属于原点位")
	}
}

// agent 漏返某个 OID 时,该点位标 bad,不能留空洞让后面的值顶上来。
func TestReadGetBatch_MissingOIDMarkedBad(t *testing.T) {
	pts, f := getPoints(4)
	f.omit[normalizeOID(pts[1].OID)] = true
	data, fail := runBatch(f, pts)

	assert.Equal(t, 4, len(data))
	assert.Equal(t, 1, fail)
	assert.Equal(t, "bad", data[1].Quality)
	assert.Equal(t, pts[1].Name, data[1].Name, "漏返时槽位仍须属于原点位")
	// 其余点位不受影响。
	assert.Equal(t, 0, data[0].Value)
	assert.Equal(t, 20, data[2].Value)
	assert.Equal(t, 30, data[3].Value)
}

// NoSuchObject 是逐变量错误:该点位 bad,整批不受影响。
func TestReadGetBatch_NoSuchObjectIsPerPoint(t *testing.T) {
	pts, f := getPoints(3)
	delete(f.values, normalizeOID(pts[2].OID)) // agent 认得 OID 但无此对象
	data, fail := runBatch(f, pts)

	assert.Equal(t, 3, len(data))
	assert.Equal(t, 1, fail)
	assert.Equal(t, "bad", data[2].Quality)
	assert.Equal(t, "good", data[0].Quality)
	assert.Equal(t, "good", data[1].Quality)
}

// 带前导点与不带的应视为同一 OID(配置常省略,agent 常返回带点形式)。
func TestNormalizeOID(t *testing.T) {
	assert.Equal(t, "1.3.6.1.2.1.1.5.0", normalizeOID(".1.3.6.1.2.1.1.5.0"))
	assert.Equal(t, "1.3.6.1.2.1.1.5.0", normalizeOID("1.3.6.1.2.1.1.5.0"))
	assert.Equal(t, "1.3.6.1.2.1.1.5.0", normalizeOID("  .1.3.6.1.2.1.1.5.0  "))
	assert.Equal(t, "", normalizeOID(""))
}

// 单点位也走批量路径,只发一次请求(不该因为"只有一个"就绕开)。
func TestReadGetBatch_SinglePoint(t *testing.T) {
	pts, f := getPoints(1)
	data, fail := runBatch(f, pts)

	assert.Equal(t, 1, len(data))
	assert.Equal(t, 0, fail)
	assert.Equal(t, 1, f.calls)
	assert.Equal(t, 0, data[0].Value)
}

// 恰好等于上限时不应多发一次空请求。
func TestReadGetBatch_ExactlyChunkSize(t *testing.T) {
	pts, f := getPoints(maxOIDsPerGet)
	data, _ := runBatch(f, pts)

	assert.Equal(t, maxOIDsPerGet, len(data))
	assert.Equal(t, 1, f.calls)
	assert.Equal(t, []int{maxOIDsPerGet}, f.sizes)
}

// fakeWalker counts Walk calls; onCall(call) 非 nil 时该次 walk 以该错误失败,
// 否则回一个 PDU 模拟成功的遍历。
type fakeWalker struct {
	onCall func(call int) error
	calls  int
}

func (f *fakeWalker) Walk(rootOid string, fn gosnmp.WalkFunc) error {
	f.calls++
	if f.onCall != nil {
		if err := f.onCall(f.calls); err != nil {
			return err
		}
	}
	return fn(gosnmp.SnmpPDU{Name: "." + rootOid + ".1", Type: gosnmp.Integer, Value: 42})
}

// walk 超时后,剩余点位(walk 和 get)直接标 bad:get 不再收集去批量读,
// 后续 walk 也不再各等一个完整超时窗口。
func TestWalkPoints_TimeoutMarksRest(t *testing.T) {
	pts := []Point{
		{Name: "w0", OID: "1.3.6.1.2.1.2.2", Op: "walk"},
		{Name: "w1", OID: "1.3.6.1.2.1.4", Op: "walk"},
		{Name: "w2", OID: "1.3.6.1.2.1.6", Op: "walk"},
		{Name: "g0", OID: "1.3.6.1.2.1.1.5.0"},
	}
	f := &fakeWalker{onCall: func(call int) error {
		if call == 2 {
			return errors.New("request timeout (after 0 retries)")
		}
		return nil
	}}
	perPoint := make([][]Data, len(pts))
	getIdx, failCount, lastErr, timedOut := walkPoints(f, pts, perPoint, nil)

	assert.Equal(t, 2, f.calls, "超时后不应继续 walk 后续点位")
	assert.True(t, timedOut)
	assert.Empty(t, getIdx, "超时后 get 点位不应再收集去批量读")
	assert.Equal(t, 3, failCount)
	assert.True(t, iot_points.IsTimeoutErr(lastErr))
	assert.Equal(t, "good", perPoint[0][0].Quality)
	for i := 1; i < 3; i++ {
		assert.Equal(t, "bad", perPoint[i][0].Quality, "第 %d 个 walk 点位", i)
		assert.Equal(t, pts[i].Name, perPoint[i][0].Name)
	}
	assert.Equal(t, "bad", perPoint[3][0].Quality)
	assert.Equal(t, pts[3].Name, perPoint[3][0].Name)
}

// 非超时的 walk 错误不短路:后续 walk 照常执行,get 点位照常收集。
func TestWalkPoints_NonTimeoutErrorContinues(t *testing.T) {
	pts := []Point{
		{Name: "w0", OID: "1.3.6.1.2.1.2.2", Op: "walk"},
		{Name: "w1", OID: "1.3.6.1.2.1.4", Op: "walk"},
		{Name: "g0", OID: "1.3.6.1.2.1.1.5.0"},
	}
	f := &fakeWalker{onCall: func(call int) error {
		if call == 1 {
			return errors.New("walk returned no results")
		}
		return nil
	}}
	perPoint := make([][]Data, len(pts))
	getIdx, failCount, _, timedOut := walkPoints(f, pts, perPoint, nil)

	assert.False(t, timedOut)
	assert.Equal(t, 2, f.calls)
	assert.Equal(t, []int{2}, getIdx, "get 点位应照常收集")
	assert.Equal(t, 1, failCount)
	assert.Equal(t, "bad", perPoint[0][0].Quality)
	assert.Equal(t, "good", perPoint[1][0].Quality)
}
