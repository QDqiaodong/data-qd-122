# Static archive fixity audit v1

为档案保管人员核验明确清单中的文件身份与当前载荷，输出每文件核验结果和未列入清单的条目。
与档案全文检索无关，不抽取文档内容或建立搜索索引；这里只读字节并验证大小/SHA256。
manifest含payload_root相对目录和entries(path,bytes,sha256)。路径为相对POSIX段，无绝对/空段/./../反斜杠，
文本<=128字符；sha256为64位小写十六进制，bytes=0..8MB。清单最多2000项，总期望/实读<=32MB。
每文件读取<=8MB，目录库存<=5000项。输出报告必须在payload树外，不能覆盖manifest或载荷。

清单重复路径、错误哈希格式、根目录缺失/符号链接是契约失败，退出2且旧报告保留。
成员缺失、大小/哈希不符、符号链接、非普通文件/非目录父级是审计发现，正常输出，不修改载荷。
未列入清单的普通文件、符号链接及特殊条目均报告；普通目录是结构，不算多余文件。
不跟随任何载荷符号链接，未列入链接不会访问其目标。inventory_clean同时要求清单全通过且无多余条目。
all_manifest_files_verified仅表示清单项，不代表清单完整性。空清单可核验但仍列多余文件。

SHA256来源是调用者提供的可信参考，不是数字签名；不证明作者、年代、来源或未曾恶意修改。
manifest不是外部认证证书。static模式输入要求静态可信本地树，不做恶意并发文件切换沙箱或挂载边界隔离。
I/O权限、超限或读失败属于执行失败；不把未读文件伪报为verified。

## 捕获模式

`--capture-mode static`（默认）保持本文件上述全部v1契约，报告结构不变。
`--capture-mode guarded`用于清单目录可信不变、载荷树核验期间可能被写入或替换的场景：
锚定根目录描述符、逐段O_NOFOLLOW不跟随符号链接、O_NONBLOCK保证FIFO不阻塞，
采集前后全树快照与每文件读取前后比较路径、类型、设备号/inode、大小、纳秒mtime/ctime及实读长度；
任一观测变化或I/O失败退出2并保留旧报告。成功报告顶层带`capture_mode:"guarded"`、
结果带`observed_stable:true`，仅保证采样点观测稳定，不保证采样间不可观测改写。
细节、边界与竞态测试见 [guarded-mode.md](guarded-mode.md)。
两种模式共享清单校验与资源上限；稳定的缺失、链接、哈希差异在两种模式下都是同样的审计发现。

fixture3个清单项：notes.txt verified，changed.txt同大小digest_mismatch，missing.bin missing；
unlisted.txt作为未列项。演示预期inventory_clean=false，这是成功发现差异而非命令失败。
核验命令本身没有修复/回写或基线清单生成；签名链、远端对象存储或定期调度也不在范围内。
另有独立的 `restore` 子命令从静态只读副本按本清单规则重建档案包（不改写被核验载荷树），
其计划格式、状态机、崩溃续跑与发布语义见 [restore-protocol.md](restore-protocol.md)。
`evidence-ingest` / `evidence-query` 子命令把**既有报告**按核验事件与修订归档到 SQLite，
只读报告、按观测截止与知识截止返回单份整报告中的路径结论；NDJSON 格式、双截止语义、
索引与重试见 [evidence-store.md](evidence-store.md)。
