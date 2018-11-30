重写 PyDrcom
===

# 包结构

```
__main__        主模块
utils/          utils 包
    config      读写, 解析配置文件或命令行
    lan         有线连接
    log         处理日志
    wire        连接 WiFi
```

## config 模块

所有内容封装到一个类 `Setting` 中, 在实际使用时, 创建了一个实例 `Application`, 要求保存以下数据:

```python
# 与上网有关的, 是 Drcom 运行所需的参数

Application.username = ""   # 认证账户 用户名       配置文件或命令行
Application.password = ""   # 认证账户 密码         配置文件或命令行
Application.dns = "8.8.8.8" # 自定义 DNS 服务器     配置文件或命令行
Application.dhcp_server = "0.0.0.0" # 自定义 DHCP IP 地址分配服务器         配置文件或命令行覆盖

Application.host_name = ""  # 本机 name, 对运行无影响       自动配置, 配置文件或命令行覆盖
Application.host_os = ""    # 本机操作系统          自动配置, 配置文件或命令行覆盖
Application.mac = 0x123456789abc        # 本机 mac (网卡物理地址)               自动配置, 配置文件或命令行覆盖

Application.server = ""     # 认证服务器地址        自动配置或配置文件
Application.host_ip = ""    # 本机 IP 地址          自动配置

## 以下勿动 ##
Application.CONTROLCHECKSTATUS = b'\x20'    # 对应字符 空格
Application.ADAPTERNUM = b'\x07'            # 对应控制字符 BELL
Application.KEEP_ALIVE_VERSION = b'\xdc\x02'
Application.AUTH_VERSION = b'\x0a\x00'
Application.IPDOG = b'\x01'
Application.ror_version = False
## END 以下勿动 ##

# 与 PyDrcom 读写配置文件或命令行有关的
Application.CONFIG_FILE # 命令行

# 与 PyDrcom 日志有关的

Application.LOG_FILE    # 配置文件或命令行
Application.LOG_ALLWAYS_SAVE   # 配置文件或命令行

# 与 PyDrcom 启动模式有关的
Application.CONNECTION_MODE = 'wire' or 'lan'     #配置文件或命令行
```

### 根据本机设置, 自动配置

#### mac 地址

使用 uuid 模块

```python
from uuid import getnode
node = getnode() # 获取硬件地址, 返回 48-bit 的整数
# 可以直接使用, 也可以使用 `hex()` 转为 16 进制(字符串)
# 使用 uuid.UUID 转为 16 进制
from uuid import UUID
mac_uuid = UUID(int=node) # 使用 UUID 转化为 16 进制(UUID 规范)
mac = mac_uuid.hex[-12:] # 只取 .hex 属性的最后 12 位, 前面都是 0
# 获得了字符串表示的 MAC 地址(16进制)
```

#### host_os host_name

使用 platform 模块

```python
from platform import uname
uname_obj = uname()
host_os = uname_obj.system
host_name = uname_obj.node
```

#### host_ip

获取当前 IP 地址, 利用 socket 的特性, 在构建 socket 包向外连接时, 会将自身 IP 地址封装在 socket 头部.

所以, 利用该特性, 构建一个向外的连接 (如果是连接至 localhost, 那么会封装 localhost 本身, 一般是 `'127.0.0.1'`, 所以一定得连接到外网.

```python
import socket

s = socket.socket(
                socket.AF_INET, # IPv4
                socket.SOCK_DGRAM
)
s.connect(('8.8.8.8', 80))      # 参数是一个元组, [0] 是连接目标的 IP 地址(str), [1] 是目标端口
got = s.getsockname()           # 返回一个元组, [0] 是自身 IP, [1] 是自身端口
ip = got[0]
s.close()                       # 使用 close 关闭连接, 否则一直占用端口
```

#### server



### 自动生成配置文件模板

`format` 函数接受的命名参数中, 若在模板字符串中没有定义, 会被忽略. 因此, 直接获取 `Setting` 类的属性即可.

但是, 不能使用 `__dict__` 方法, 此方法无法获取一些属性, 为此, 自定义了一个方法 `getAttributes`
