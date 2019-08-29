# 简介

PyDrcom 是一个使用 Python3 的 Drcom 第三方客户端. 适用于 D 版。

参考了 [drcom-generic](https://github.com/drcoms/drcom-generic/) 中的脚本。

# 安装

```sh
git clone https://github.com/zombie110year/pydrcom.git
cd pydrcom
python setup.py install --user
```

# 使用方法

编辑配置文件后, 运行程序.

```sh
# 查看使用方法
drcom --help
# 直接运行
drcom start
# 查看日志
drcom log
# 由 WireShark 抓包生成配置文件
drcom analyse example.pcapng
```

## 配置条目

使用以下命令从 WireShark 抓包生成配置文件模板, 保存在当前目录下的 `drcom.toml` 中。

```sh
drcom analyse example.pcapng
```

如果从抓包自动生成失败的话，可以从默认配置手动修改，先进入 Python 交互解释器，
然后将默认配置保存至文件。

```python
from drcom.config import DrcomConfig
from pathlib import Path
config = DrcomConfig()
config.dump(Path("drcom.toml"))
```
编辑 drcom.toml 文件. 由于 toml 解析器将字节理解为数组，因此需要将字节编辑为:

```python
# Python 中的字节
b'\x01\xfe'
# toml 中的数组
[0x01, 0xfe]
```

# 开源协议

drcom: [GPLv3](LICENSE)

toml: [MIT](toml/LICENSE) [HOMEPAGE](https://github.com/uiri/toml)
