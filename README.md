# 简介

PyDrcom 是一个使用 Python3 的 Drcom 第三方客户端. 适用于 **无线连接**.

属于个人学习作品.

参考了 [drcom-generic](https://github.com/drcoms/drcom-generic/)

# 使用方法

从 drcom 目录中拷贝出来文件, 将配置项填写好, 然后直接运行即可.

## 配置条目

```python
## 用户名与密码
username = None
password = None

## 连接方式, 可选 wire(无线网络), lan(有线连接)
CONNECTION_MODE = None

## 网络配置
server = None
dns = "8.8.8.8"
dhcp_server = '0.0.0.0'
host_name = "MyComputer"
host_os = "MySystem"
mac = 0x1
bind_ip = "0.0.0.0"
port = 61440

## 日志保存
## 若 LOG_ALLWAYS_SAVE = True, 则所有输出至 stdout,stderr 的内容都会保存到 LOG_FILE
LOG_FILE = None
LOG_ALLWAYS_SAVE = False

## Drcom 客户端伪装
CONTROLCHECKSTATUS = b'\x20'
ADAPTERNUM = b'\x07'
KEEP_ALIVE_VERSION = b'\xdc\x02'
AUTH_VERSION = b'\x0a\x00'
IPDOG = b'\x01'
SALT = ''
```

# 待办

- [ ] 完成 wire 模块
- [ ] 完成 lan 模块
- [ ] config 模块
    - [ ] 自动检测 Drcom 认证服务器地址
- [ ] 测试 Windows
- [ ] 测试 Linux
