from argparse import ArgumentParser
from os.path import exists

config_template = r"""
# 登陆校园网的账号密码
username = "example"
password = "passwd"

# 系统设置
##! Drcom 认证服务器的 IP 地址
server = "10.254.7.4"

dns = "8.8.8.8"
dhcp_server = "0.0.0.0"

## 计算机名, 没有严格要求, 被用于心跳包加密
host_name = "faqdrcom"

## 操作系统名, 没有严格要求, 被用于心跳包加密
host_os = "Windows"

##! 本机 IP 地址, 需要为本机设置静态 IP. 除了 Socket 通讯, 也被用于心跳包加密
host_ip = "10.253.194.204"

## 网卡 mac 地址, 为任意十六进制数, 除此之外没有严格要求, 用于心跳包加密
mac = 0x1

bind_ip = "0.0.0.0"

## 绑定端口, 如果发生端口已被占用的情况就换一个
port = 61440

## 网卡名称, 非 Linux 无用. 可以不进行设置.
nic_name = ""

#! 客户端伪装参数 各学校可能不同
CONTROL_CHECK_STATUS = b'\x20'
ADAPTER_NUM = b'\x07'
KEEP_ALIVE_VERSION = b'\xdc\x02'
AUTH_VERSION = b'\x0a\x00'
IPDOG = b'\x01'
SALT = ""
ror_version = False
"""

class Config:
    __doc__ = config_template

def getCliArgs():
    parser = ArgumentParser(
        prog="Drcom Python Client",
        description="这是 Drcom 的 Python 客户端, 在命令行启动, 停止运行则按 Ctrl+C"
    )
    parser.add_argument(
        "-c", "--config",
        dest="config_file",
        help="指定配置文件 优先级 当前目录 > ~/.config/drcom/ > /etc/drcom 中的 drcom.conf",
        required=False,
        metavar="path/to/drcom.conf"
    )
    parser.add_argument(
        "--generate-config",
        dest="gen_config_file",
        help="在当前目录下生成配置文件模板",
        required=False,
        action="store_true",
        default=False
    )
    arg = parser.parse_args()
    return arg

def getConfigFileContent(path):
    conf = Config()
    paths = (
        path,
        "./drcom.conf",
        "~/.config/drcom/drcom_conf.py",
        "/etc/drcom/drcom_conf.py"
    )

    for file in paths:
        if exists(file):
            code = compile('', file, 'exec')
            break

    
    exec(code, conf.__dict__)

    return conf

def configure():

    arg = getCliArgs()

    if arg.gen_config_file:
        with open("./drcom.conf", "wt", encoding="utf-8") as file:
            file.write(config_template)
            file.write("\n")
        exit(0)
    else:
        return getConfigFileContent(arg.config_file)
