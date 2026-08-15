# third_party/iec104

vendored 自 `github.com/wendy512/iec104@v1.0.4`（10 个源文件，无功能删改），
经 go.mod `replace` 指向本目录。

## 补丁清单

### client/core.go — Connect() 建连竞态修复

原实现顺序：`client104.Start()`（启动内部连接 goroutine）→ `SetOnConnectHandler(...)`。
Start 起的 goroutine 会读取 onConnectHandler 字段，而该字段在 goroutine 启动后才被写入，
二者无同步原语 → `go test -race` 必报 data race（interface 值双字写入，理论上有撕裂读风险）。

补丁：把 handler 设置代码块移到 `Start()` 之前。goroutine 创建前的写入天然建立
happens-before，竞态消除。行为不变（handler 仅在连接成功后被调用）。

## 注意事项

- 库本体已 vendor 到 ../go-iecp5（含 server WaitGroup 竞态修复，见其 VENDOR.md），
  本目录与其一并构成完整补丁，仓库与下游均生效，不再依赖上游发版。
- 根治需要上游修复：建议向 https://github.com/wendy512/iec104 提交 issue/PR
  （即本目录 client/core.go 的改动），上游合并发版后可删除本 vendored 副本与 replace。
