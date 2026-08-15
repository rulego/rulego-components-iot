# third_party/go-iecp5

Vendored from `github.com/wendy512/go-iecp5@v1.2.6`（LGPL-3.0，LICENSE 原样保留；
仅拷贝 asdu/clog/cs104 三个包，cs101 与 _examples 未使用故未纳入）。

采用「包拷贝进本模块」而非 go.mod `replace`：replace 只在主模块生效，
下游依赖方拿不到补丁；直接改 import 路径后本仓库与所有下游都使用本目录代码。

## 补丁清单

### cs104/server.go — WaitGroup 数据竞态修复

上游 v1.2.6（最新版，未修复）：accept 循环里的 `sf.wg.Add(1)`（无锁）与
`Close()` 里的 `sf.wg.Wait()`（无锁）可并发执行。WaitGroup 计数器本身非并发安全，
`Add` 与 `Wait` 无同步交错是文档明确的数据竞态——`go test -race` 下 iec104
mock server 的 Start/Stop（external/iec104 测试）必现：

    WARNING: DATA RACE
    Write at cs104/server.go Close() -> sf.wg.Wait()
    Previous read at cs104/server.go ListenAndServer() -> sf.wg.Add(1)

补丁：新增 `wgMu sync.Mutex` 串行化 `wg.Add`（accept 循环）与 `wg.Wait`（Close）。
session goroutine 的 `wg.Done()` 不需要 wgMu，无死锁路径：Wait 持锁等待期间，
新连接的 Add 会短暂阻塞到 Wait 返回，属可接受的停机窗口。

cs104/client.go 与 server_session.go 中的 `wg.Add(3)/Wait()` 均在同一 goroutine
的 `run()` 内先后执行，自带 happens-before，无竞态，未改动。

### asdu/mproc_test.go — 上游自带的两个错误测试

上游从不运行自身测试，两处 CP56Time2a 用例的类型常量互相抄反（确定性失败）：
TestSingleCP56Time2a 期望 M_ST_TB_1（步位置），TestStepCP56Time2a 期望 M_SP_TB_1（单点）。
按协议语义互换为正确值：单点+CP56=M_SP_TB_1(30)，步位置+CP56=M_ST_TB_1(32)。
仅改测试期望，库代码未动。

## 升级注意

如需同步上游新版本：拷贝新版三包覆盖本目录 → 重写 import 路径
（`github.com/wendy512/go-iecp5` → 本仓库路径）→ 重放上述补丁。
