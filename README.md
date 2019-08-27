# 简介

PyDrcom 是一个使用 Python3 的 Drcom 第三方客户端. 适用于 **无线连接**.

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

# 开源协议

[GPLv3](LICENSE)
