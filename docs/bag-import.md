# BagIt 1.0 导入（bag-import）协议

`archive-fixity bag-import` 把一个 BagIt 1.0 包转换为本仓核验命令可直接使用的
审计清单（`{payload_root, entries[path,bytes,sha256]}`），**只读**包内全部文件，
不创建、修改、删除包内任何条目。信任边界与 `static` 捕获模式一致：包目录静态、
可信、本地；不防御核验期间的对抗性并发换文件。

## 1. 输入与命令

```sh
archive-fixity bag-import --bag path/to/bag --output run/manifest.json
```

只接受一个目录（`--bag`）和一个输出文件路径（`--output`）。读取：

| 文件 | 要求 |
| --- | --- |
| `bagit.txt` | 必须存在；UTF-8；恰好 `BagIt-Version: 1.0` 与 `Tag-File-Character-Encoding: UTF-8` 两个字段 |
| `manifest-sha256.txt` / `manifest-sha512.txt` | 至少一个；可同时存在 |
| `tagmanifest-sha256.txt` / `tagmanifest-sha512.txt` | 可选；可同时存在 |
| `bag-info.txt` | 可选；其中 `Payload-Oxum` 若出现则参与核对 |

`data/` 必须是包根下的真实目录。包内**任何**符号链接、FIFO、套接字或设备文件都
直接拒绝（先 `lstat` 全树扫描，之后才读取字节），不跟随链接、不访问链接目标。
可接受的清单算法只有 `sha256`、`sha512`；出现 `manifest-md5.txt` 等其它算法
（含大小写变体形成的重复项）即拒绝。

## 2. 校验内容

1. **版本与编码**：`bagit.txt` 的版本必须为 `1.0`，标签文件编码声明必须为 `UTF-8`；
   重复字段、未知字段、空行均报错。
2. **摘要行**：每个清单行为 `<小写十六进制摘要><空白><路径>`；摘要长度与算法一致
   （sha256 64 位、sha512 128 位）。路径为包根相对 POSIX 路径，拒绝绝对路径、
   空段、`.`/`..` 段、反斜杠、首尾空白和超过 128 字符的名字。同一清单内重复路径拒绝。
3. **路径归属**：payload 清单只能列 `data/` 下的文件；tag 清单不得列 `data/` 下的
   payload 路径，也不得列它自己。
4. **路径集合与缺项/多余项**：`data/` 的实际普通文件集合必须与**每个** payload
   清单的路径集合完全相等——清单列出但磁盘不存在是缺项，磁盘存在但清单未列是多余项。
5. **摘要与长度**：每个 payload 文件按块读取一次，同时更新该包声明的所有算法；
   任一算法的实算摘要与清单不符即失败；实读字节数必须等于扫描时的长度，文件在读取
   期间变长/变短同样失败。
6. **Payload-Oxum**：若 `bag-info.txt` 声明 `Payload-Oxum: <字节数>.<文件数>`，
   则总字节数必须等于全部 payload 实读字节之和、文件数必须等于 `data/` 文件数；
   `Payload-Oxum` 重复或格式非法即拒绝。
7. **tagmanifest 覆盖**：只要存在任一 tagmanifest，它必须覆盖全部**非 payload、
   非 tagmanifest** 的标签文件（即包根及子目录中的其它普通文件，如 `bagit.txt`、
   `bag-info.txt`、payload 清单本身）。tagmanifest 之间允许互相列出（其摘要同样
   核对），但不要求、也不允许列出它自己。被列出的标签文件必须存在且摘要一致。

失败诊断尽量给出**文件与行号**，例如
`manifest-sha512.txt:7: digest mismatch for data/sub/b.bin (sha512)`、
`bag-info.txt:1: Payload-Oxum byte count 260 != 261`；路径集合类错误没有可指认的
行时给出来源清单文件名和路径（如 `data/extra.bin: payload file is not listed in
manifest-sha256.txt`）。

## 3. 输出与发布

成功时写出：

```json
{
  "payload_root": "data",
  "entries": [{"path": "sub/b.bin", "bytes": 256, "sha256": "..."}]
}
```

- 顶层键与顺序固定（`sort_keys=True`、两空格缩进、末尾换行），可逐字节复现；
- 条目按路径字典序排列，`path` 相对 `payload_root`（`data/` 前缀被去掉）；
- `sha256` 一律来自本次实读字节；只声明 sha512 的包也会计算并写入 sha256；
- 发布前用 `model.validate_entries` 复核一遍生成清单（路径语法、重复、单文件/总量
  上限），因此产物一定满足核验与恢复命令的清单契约。

stdout 输出摘要（退出 0）：

```json
{
  "schema_version": 1,
  "manifest": "/abs/run/manifest.json",
  "manifest_sha256": "<目标清单文件字节的 SHA256>",
  "manifest_bytes": 465,
  "bagit_version": "1.0",
  "payload_root": "data",
  "algorithms": ["sha256","sha512"],
  "tag_algorithms": ["sha256"],
  "payload_files": 3,
  "payload_bytes": 261,
  "payload_oxum": "261.3",
  "tag_files": 3
}
```

`manifest_sha256`/`manifest_bytes` 是**写出的清单文件字节**的摘要与长度，可用于
把后续核验结果绑定到这一份清单；`payload_oxum` 为 `null` 表示包里没有声明。

发布方式与核验报告相同：先在输出目录写同目录临时文件、`fsync`，再 `os.replace`
原子替换。因此：

- 全包校验通过之前**从不触碰**输出路径；
- 任一校验失败（含最后一条路径）都退出 2，旧清单原样保留，不留下临时文件；
- 输出路径不得是符号链接、不得是已存在的目录，也不得位于包目录树内（包括经由
  符号链接父目录指回包内的路径）；这些检查在读取任何文件之前完成。

## 4. 单遍读取 / 分阶段读取的取舍

实现是**分阶段读取、载荷单遍**：

1. 先全树 `lstat` 扫描得到文件集合与长度，并读取根级标签文件做元数据/清单解析；
2. 再按路径顺序逐个读取 payload 文件，一次读完同时更新所有声明算法；
3. 最后（仅当有 tagmanifest 时）读取并核对标签文件。

选择单遍读 payload 的原因：

- **一致性**：sha256 与 sha512 两套清单必须看到同一批字节。分开两遍读会让“两遍之间
  文件被替换”表现为两条互相矛盾的结论；单遍读取下同一份字节只能得出一种结果。
- **成本**：包总量上限 32 MB、单文件 8 MB，内存与 I/O 都受控；不需要为了性能把
  payload 读两遍。
- **失败早退**：一旦某文件摘要不符立即失败，不必先跑完另一种算法。

代价与边界：

- 不能“先只验 sha256 快速筛一遍再决定是否算 sha512”，失败诊断只报第一个发现问题。
- 读取顺序是“清单集合与包结构 → payload 字节 → 标签字节”。标签文件在 payload
  之后才核对，所以一个被篡改的 tagmanifest 不会掩盖 payload 错误，反之 payload
  错误也会先于标签错误报告。
- 包在读取期间被并发改写时，只能通过“实读长度 vs 扫描长度”和“读取后 `fstat`
  大小 vs 实读字节数”发现；不提供 guarded 模式的 inode/时间戳级观测。需要更强
  保证时应在包静默窗口运行。

## 5. 资源上限

沿用核验命令：单文件 ≤8 MB、payload 期望与实际总量 ≤32 MB、payload 清单 ≤2000 项、
整树库存 ≤5000 项、每个清单 ≤5000 项、标签文件 ≤8 MB、标签摘要总计 ≤32 MB。
超限是契约失败（退出 2），不会发布半成品。

## 6. 失败语义与测试

| 场景 | 结果 |
| --- | --- |
| 版本不是 1.0、编码不是 UTF-8、缺 `bagit.txt`/清单、无 `data/` | 退出 2，旧清单保留 |
| 摘要格式/长度错误、路径越界或重复、缺项、多余项 | 退出 2，指出文件（与行） |
| Payload-Oxum 字节数或文件数不符 | 退出 2，指出 `bag-info.txt` 行号 |
| 任一 payload/标签摘要不符 | 退出 2，指出清单文件与行号 |
| tagmanifest 漏列或列出缺失的标签文件 | 退出 2 |
| 包内任意符号链接或特殊文件 | 退出 2 |
| 成功 | 原子发布；stdout 给出清单 SHA256 与字节数；包内文件逐字节不变 |

测试（`tests/test_bag.py`，端到端经 CLI 子进程）覆盖：单算法与 sha512-only 转换、
双算法 pack 的成功转换、生成清单被 `--source` 核验与 `restore` 接受、重跑字节一致、
包目录快照前后不变、双算法中仅 sha512 被篡改、标签文件篡改、最后一条 payload 错误
后旧清单保持且无临时文件、输出写在包内/符号链接被拒、链接与特殊文件、所有计数与
上限错误。另有进程内测试证明双算法包的每个文件只被读取一次。
