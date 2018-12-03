# 简介

PyDrcom 是一个使用 Python3 的 Drcom 第三方客户端. 适用于 **无线连接**.

参考了 [drcom-generic](https://github.com/drcoms/drcom-generic/)

# 安装

```sh
git clone https://github.com/zombie110year/pydrcom.git
cd pydrcom
python setup.py install --user
```

# 使用方法

编辑配置文件后, 运行程序.

```sh
drcom -h # 查看使用方法
drcom # 直接运行
```

## 配置条目

使用以下命令生成配置文件模板, 产生的文件在当前工作目录下.

```sh
drcom --generate-config
```

# 待办

- [x] 完成 wire 模块
- [ ] 完成 lan 模块
- [ ] config 模块
    - [x] 生成配置文件模板
    - [ ] 自动检测 Drcom 认证服务器地址
- [ ] 测试 Windows
    - [x] Windows 10
- [ ] 测试 Linux
    - [x] Ubuntu 16.04 LTS amd64

# 开源协议

[GPLv3](LICENSE)
