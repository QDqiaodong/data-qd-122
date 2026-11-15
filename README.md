# data-qd-122 · 数字档案完整性核验

Manifest-based digital archive fixity auditing。业务输入、计算和当前边界详见 [数据契约](docs/contract.md)。

## 安装与演示

Python >=3.11，运行和测试仅用标准库；先确认 `python3 --version`。
每仓建立独立环境，构建工具锁版本。首次安装无公共缓存时可能联网；业务运行不访问网络。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-build.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps .
.venv/bin/python -m pip check
.venv/bin/archive-fixity --source fixtures/input.json --output run/report.json
.venv/bin/archive-fixity --source fixtures/input.json --output run/report-guarded.json --capture-mode guarded
.venv/bin/archive-fixity restore --plan run/restore-plan.json
.venv/bin/python -m unittest discover -s tests -v
```

本地已有wheel时，安装构建工具可加 `--no-index --find-links <公共wheel缓存目录>`。
修改源码后重新安装。本仓不共享其他仓环境，不依赖Docker、外部账号或持续服务。

输入JSON最多8MB，拒绝重复键、非有限数值和未定义字段；源字节SHA256随结果保留。
输出是可独立读取的JSON；成功后原子替换，输入/计算失败退出2并保留旧报告。
输入和输出不得相同，输出符号链接拒绝。单操作者批处理，不承诺并发发布或断电恢复。
同输入重跑不累加。测试使用临时目录，运行产物在忽略的run/。

src/archive_fixity/model.py 为业务模型，相关算法模块独立组织；common.py 提供受限JSON及报告发布，
cli.py 衔接数据链路。fixtures 为明确自制样例，代码与样例采用MIT许可。

## 恢复（restore）

`archive-fixity restore --plan <计划.json>` 从静态只读副本按可信清单重建档案包：
计划含清单路径、有序副本目录、目标与状态目录，相对路径基于计划目录；目标与状态
必须在输入树（清单目录与全部副本树）之外且互不包含。按副本顺序选取大小与SHA256
均匹配的普通文件，缺失/损坏/链接自动换源，无合格来源则失败。全程只在状态目录
暂存，分块复制并校验写入字节，包内附逐项来源收据；清单SHA、目标与有序副本绑定
身份，变化拒绝续跑；续跑重验已完文件字节而非信任日志；发布前重验全包，再同盘
原子改名到不存在的目标，发布未记账的中断可被识别并幂等成功，拒绝覆盖其他目录。
协议、状态布局、故障点与边界详见 [docs/restore-protocol.md](docs/restore-protocol.md)。

## 业务与样例结果

清单3项：1项verified、1项同大小哈希变更、1项missing，另发现unlisted.txt。
files.py执行受限字节捕获与无链接遍历，model.py给出差异；只读载荷、不修复。

## 证据库（evidence store）

`archive-fixity evidence-ingest` 将既有核验报告按“核验事件 + 修订”批量写入 SQLite，
每批单事务提交并分配递增知识序号；坏行整批回滚，同修订同内容幂等、不同内容拒绝。
`evidence-query` 按观测截止 T 与知识截止 S 返回**单份整报告**中的路径结论，
区分无观测 / 未列清单 / 明确 missing，不逐路径拼接历史。
格式、双截止语义、索引与重试详见 [docs/evidence-store.md](docs/evidence-store.md)；
规模自检用 `PYTHONPATH=src:tests python3 tests/evidence_benchmark.py --revisions 100000
--files-per-report 100`（10 万修订/千万文件态，约 97 秒，非单元测试）。

```sh
.venv/bin/archive-fixity evidence-ingest --db run/evidence.sqlite3 --batch run/revisions.ndjson
.venv/bin/archive-fixity evidence-query --db run/evidence.sqlite3 --archive arch-01 \
    --path docs/a.txt --observed-before 2026-01-03T00:00:00Z --knowledge-cutoff 42
```

## 捕获模式

默认`--capture-mode static`保持原静态契约与报告结构不变。
`--capture-mode guarded`面向清单目录可信、载荷树核验期间可变的场景：锚定根描述符、
逐段不跟随符号链接、FIFO不阻塞，采集前后全树指纹与每文件读取前后属性/实读长度比对，
任一观测变化或I/O失败退出2并保留旧报告；成功标明`observed_stable`，仅保证采样点观测。
一致性边界、失败语义与同步屏障竞态测试见 [docs/guarded-mode.md](docs/guarded-mode.md)。
