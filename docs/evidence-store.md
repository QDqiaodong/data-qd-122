# 证据库（evidence store）v1

`archive-fixity evidence-ingest` / `evidence-query` 把**已有的核验报告**按核验事件归档到本地
SQLite，并按“观测截止 T + 知识截止 S”回答单个路径在某一时刻的结论。证据库只读报告，
不重新读取载荷、不修复、不生成清单，也不改变历史核验命令的输入/输出/退出码。
仅标准库（`sqlite3`、`json`、`zlib` 等），单操作者批处理。

## 1. 观测、修订与知识序号

**核验事件**由 `(archive_id, verification_id)` 标识。同一核验的两件事永久固定：

- `archive_id`（档案 ID）；
- `observed_at`（该次观测的 UTC 时刻）。

两者一经入库，后续修订必须完全一致；任何不一致都使整批失败。

**修订号** `revision` 从 1 开始、逐次加一、不允许空洞：

| 行形态 | 含义 |
| --- | --- |
| `report` | 一份完整核验报告，替换该核验此前的整份报告 |
| `retracted: true` | 该修订使观测失效（撤回），不携带报告 |

同修订同内容（报告规范化字节逐字节相同，或同为撤回）再次提交是**幂等**的：不新增行、
不前进知识序号，摘要中计为 `idempotent`。同修订不同内容（含报告/撤回互换、`observed_at`
或 `archive_id` 变化）是**冲突**，整批拒绝。

**知识序号**是证据库全局递增的修订序号（`revisions.revision_id`，SQLite
`AUTOINCREMENT`）。它只在批次事务提交时分配，因此：

- 一个批次内的所有行在同一事务中提交，要么全部可见、要么全部不可见；
- 坏行、冲突或任意错误使整批回滚，知识序号不前进、不留空洞（回滚会撤销
  `sqlite_sequence` 的推进），修正后用同样内容重试即可从原 `head+1` 继续；
- 重开库、复制库或重新查询都得到同一结果。

`evidence-ingest` 摘要给出本次批次的 `first_knowledge_sequence` / `last_knowledge_sequence`
与 `knowledge_head`；知识截止只能用已提交的序号。

## 2. NDJSON 批次格式

一行一个修订，UTF-8，`\n` 分隔（容忍行尾 `\r`）。空行、非 UTF-8、重复 JSON 键、非有限
数值、未定义字段、超过 16 MB 的单行都是整批失败。字段恰好为：

```json
{"archive_id":"arch-01","verification_id":"verify-2026-0007","revision":2,
 "observed_at":"2026-01-01T00:00:00Z","report":{ "...完整核验报告..." }}
{"archive_id":"arch-01","verification_id":"verify-2026-0008","revision":3,
 "observed_at":"2026-01-02T03:04:05.123456Z","retracted":true}
```

- `observed_at`：UTC ISO-8601，`YYYY-MM-DDTHH:MM:SS[.ffffff]Z` 或同样带 `+00:00` 后缀；
  非 UTC 偏移、非规范日历日期与闰秒拒绝。内部存整数微秒。
- `revision`：1..2^31-1 的整数。
- 每行恰好给出 `report` 或 `retracted:true` 之一，不能同时或都不给。

行内 `archive_id`/`verification_id` 是档案与核验的事件标签，可为任意非空、无控制字符、
≤128 字符的标识符；`report` 内部不再重复它们。

## 3. 报告结构与一致校验

`report` 必须就是现有核验命令的输出（static 或 guarded 两种模式之一），按现有结构逐字段
校验，不做宽松解释：

- 顶层 `{schema_version:1, source_sha256, result}`；guarded 报告额外带
  `capture_mode:"guarded"`，且 `result.observed_stable` 必须为 `true`。
- `result` 字段恰好为 `files`、`status_counts`、`unlisted_entries`、`manifest_files`、
  `captured_bytes`、`all_manifest_files_verified`、`inventory_clean`（guarded 另加
  `observed_stable`）。
- 每个 `files` 项的字段集合按其 `status` 决定：
  - `verified`/`mismatch`（已读）：`path,expected_bytes,expected_sha256,status,actual_bytes,
    actual_sha256,differences`；
  - `missing`/`unsafe_link`/`non_directory_parent`/`not_regular_file`（未读）：
    `path,expected_bytes,expected_sha256,status`。
- 路径沿用清单规则（规范相对 POSIX 段，无绝对/空段/`.`/`..`/反斜杠，≤128 字符）；
  SHA256 为 64 位小写十六进制；单文件 ≤8 MB；清单 ≤2000 项；已读总量 ≤32 MB；
  未列清单项 ≤5000。
- **计数校验**：`status_counts` 必须等于按状态实际计数；`manifest_files` 等于文件项数；
  `captured_bytes` 等于已读项的 `actual_bytes` 之和；`all_manifest_files_verified` 等价于
  全部 `verified`；`inventory_clean` 等价于无未列项且全部 `verified`。
- `verified` 项必须 `actual_bytes==expected_bytes`、`actual_sha256==expected_sha256`、
  `differences==[]`；`mismatch` 项的 `differences` 必须恰由大小/摘要差异推导。

因此证据库保存的是**原报告**（规范化 JSON，zlib 压缩进单个 `BLOB`）与**摘要**
（用于查询的 `statuses`、`status_counts`、`file_count`、`unlisted_count`、布尔标志、
`report_sha256`）。查询返回的整份报告与入库报告在规范化 JSON 意义上逐字节一致。

## 4. 查询语义（双截止）

`archive-fixity evidence-query --db <库> --archive <档案ID> --path <路径>
--observed-before <T> --knowledge-cutoff <S>`

严格按以下顺序选出**一份整报告**，再在其中查该路径：

1. **知识截止 S**：只考虑 `revision_id <= S` 的修订；对每个核验取其中**最后**一个修订。
   为此，在 S 时点该核验若已被撤回，它没有有效观测，即使更早的修订是报告。
2. **观测截止 T**：在这批“最后修订”中只保留 `kind='report'` 且 `observed_at <= T` 者。
3. **选择**：按 `observed_at` 降序、`verification_id` 降序取第一条；整份报告即为答案。
4. **路径查询**：在该报告的 `files` 中找路径；命中则输出该文件项（状态可为 `verified`、
   `mismatch`、`missing` 等）。未命中时再查 `unlisted_entries`：命中则记为 `not_listed`
   并给出未列项；否则同样 `not_listed` 且 `unlisted_entry:null`。

由此生硬的“逐路径拼接历史”被禁止：任何路径答案都来自同一 `verification_id` + `revision`
的整份报告，`report_sha256` 标明是哪一份。

### 三种非观测结果

| `outcome` | 含义 |
| --- | --- |
| `no_observation` | 在 S 时点没有该档案的有效观测，或所有有效观测都晚于 T |
| `not_listed` | 选中的整报告既没有该路径的文件项，也没有把它列为未列项 |
| `observed` | 选中报告带有该路径的文件项；`observation.status` 可能是 `missing` |

`not_listed` 与 `missing` 不同：前者表示该报告对该路径**完全没有记录**（例如新清单移除了
旧路径），后者表示报告明确记录了“清单要求但载荷缺失”。二者都不同于 `no_observation`
（根本没有可用的整报告）。

### 迟到、更正与撤回不泄漏

- 迟到：在 S 之后才入库的观测（哪怕其 `observed_at` 早于 T）对 S 不可见。
- 更正：S 之后的新修订不改变 S 时点的最后修订答案；S 之前的旧答案保持不变。
- 撤回：若某核验在 S 时点的最后修订是撤回，该核验对 S 无有效观测，更早的报告不会复活。
  后续修订若重新提交报告，则从该修订起恢复；早期 S 仍不受影响。
- 新清单移除旧路径：新的整报告不再列出旧路径时，以它为答案的查询返回 `not_listed`，
  不会回退到旧报告中逐路径补出。

## 5. 查询执行与规模

- 库布局：`revisions`（每修订一行，含知识序号、固定观测时刻、种类、压缩报告 BLOB 与摘要）
  加上 `verifications` 与 `evidence_meta`。索引：
  `revisions(verification_id, revision_id)` 支持“S 时点最后修订”判定，
  `revisions(archive_id, observed_us DESC, verification_id DESC)` 支持按时间选优；
  `LIMIT 1` 使查询在命中后即停。
- 查询**不把历史载入 Python**：SQLite 完成筛选，Python 只解压被选中的那**一份**报告；
  也不会逐路径回放历史。典型查询为毫秒级（10 万修订实测 0.5–26 ms，最旧截止为最坏情况）。
- 规模实测（`tests/evidence_benchmark.py`，标准库）：10 万修订 × 100 文件 =
  1000 万文件态，单事务入库约 97 秒，库约 157 MB；查询最坏（最旧截止）约 11 ms，
  最新截止约 2 ms，不随历史线性增长。
- 读取使用只读连接（`PRAGMA query_only=ON`），不写库、不留下 WAL 侧文件；写库使用
  WAL + `synchronous=FULL`，批次事务提交即持久。

## 6. 事务失败与重试

- 批次在**一个** `BEGIN IMMEDIATE` 事务中处理；任何行失败即整批回滚。
- 瞬时锁/忙（`database is locked`/`busy`/`deadlock`）按 `--retry-attempts`（默认 8）
  与 `--retry-delay`（默认 0.05 秒，指数退避，封顶 1 秒）重试；每次重试整批重读。
  非瞬时错误（坏行、冲突、结构不符）不重试。
- 失败后库保持原 `knowledge_head`；用修正后的批次重试即可，无需手工清理。
- 重开库、只读复制库、重复相同批次（幂等）都得到相同查询结果。

## 7. CLI 与退出码

```sh
archive-fixity evidence-ingest --db run/evidence.sqlite3 --batch run/revisions.ndjson
archive-fixity evidence-query  --db run/evidence.sqlite3 --archive arch-01 \
    --path docs/a.txt --observed-before 2026-01-03T00:00:00Z --knowledge-cutoff 42
```

- 成功：退出 0，stdout 为单行 JSON（`sort_keys` 排序）。ingest 摘要含 `lines`、`accepted`、
  `idempotent`、首末知识序号、`knowledge_head`；query 结果含 `outcome`、选中核验/修订/
  知识序号、`report_sha256`、完整 `report`、`report_summary`、`observation` 与
  `unlisted_entry`。
- 契约失败（坏行、冲突、结构/计数不符、库不是本版本、库/批次/输出路径为符号链接等）：
  退出 2，stderr 说明原因，库不变。
- `--knowledge-cutoff` 必须是已提交的非负序号；超出当前 head 合法（等价于当前 head），
  负数拒绝。
- 历史平面命令 `archive-fixity --source ... --output ...` 与 `restore` 子命令保持不变。

## 8. 测试

- `tests/test_evidence.py`：直接用 API 覆盖批次事务、坏行回滚、幂等/冲突、修订连续性、
  固定档案与时刻、双截止选择、三种结果、整报告不拼接、只读查询、索引命中、锁重试、
  重开/复制库稳定性。
- `tests/test_evidence_cli.py`：每条 NDJSON 行中的报告都由**真实** `archive-fixity`
  CLI 在真实载荷树上生成（含 guarded 模式），再经真实子进程 `evidence-ingest` /
  `evidence-query` 验证迟到、更正/撤回/恢复、重复冲突、批末坏行回滚、双截止，
  以及新清单移除旧路径时不回填。
- `tests/evidence_benchmark.py`：可选的十万修订 / 千万文件态规模自检，不属于单元测试。

## 9. 边界

- 证据库不验证报告是否由可信执行者产生；它只保证入库内容结构一致、可按双截止复现。
- 不提供签名、不可抵赖、跨库复制协议或并发发布；单操作者顺序入库。
- 查询答案只对已提交的知识序号负责；不得把内存中的未提交状态当成 S。
- 报告 BLOB 在查询时按记录中的 `report_size` 有界解压，并重算 SHA256；损坏的库会报错
  而不是返回可疑内容。
- 报告的 `source_sha256` 仍只是调用者提供的参考摘要，证据库不对其含义作额外背书。
