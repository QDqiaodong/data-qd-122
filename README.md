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

## 业务与样例结果

清单3项：1项verified、1项同大小哈希变更、1项missing，另发现unlisted.txt。
files.py执行受限字节捕获与无链接遍历，model.py给出差异；只读载荷、不修复。

## 捕获模式

默认`--capture-mode static`保持原静态契约与报告结构不变。
`--capture-mode guarded`面向清单目录可信、载荷树核验期间可变的场景：锚定根描述符、
逐段不跟随符号链接、FIFO不阻塞，采集前后全树指纹与每文件读取前后属性/实读长度比对，
任一观测变化或I/O失败退出2并保留旧报告；成功标明`observed_stable`，仅保证采样点观测。
一致性边界、失败语义与同步屏障竞态测试见 [docs/guarded-mode.md](docs/guarded-mode.md)。
