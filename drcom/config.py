"""Drcom 客户端配置文件相关内容

1. 读取配置文件中的字段
2. 生成配置文件
"""

from argparse import SUPPRESS, Action, ArgumentParser
from os import environ
from pathlib import Path
from platform import system
from sys import exit
import toml

from .utils import getIP, getMacAdress

DEFAULT_CONFIG_FILES = [
    Path("drcom.toml"),
    Path.home() / ".config/drcom/drcom.toml",
    Path("/etc/drcom/drcom.toml")   # 为 Linux Systemd 准备
]


class DrcomConfig:
    """DrcomConfig

    DrcomApp 使用的配置文件
    """

    def __init__(self):
        self.data = {
            "application": {
                "logging": 10,              # int
                "bind_ip": "0.0.0.0",       # 客户端必须监听网卡上所有接口
            },
            "drcom": {
                "keep_alive_interval": 15,  # int
                "server": "认证服务器",     # str
                "server_port": 61440,       # 认证服务器端口
                "username": "校园网账号",   # str
                "password": "校园网密码",   # str
                "mac": getMacAdress(),      # int
                "host_ip": getIP(),         # str
                "host_name": "F**K DRCOM",  # str
                "host_os": "DRCOM F**KER",  # str
                "dhcp": "0.0.0.0",          # str
                "dns": "8.8.8.8",           # str
            },
            "core": {
                "CONTROL_CHECK_STATUS": b"",    # bytes
                "ADAPTER_NUM": b"",             # bytes
                "IP_DOG": b"",                  # bytes
                "AUTH_VERSION": b"",            # bytes
                "KEEP_ALIVE_VERSION": b"",      # bytes
                "SALT": b"",                    # bytes
                "ROR_VERSION": False,           # bool
            }
        }

    def loads(self, string: str):
        """从 TOML 格式的字符串中加载配置
        """
        self.data = toml.loads(string)
        for key in {"CONTROL_CHECK_STATUS", "ADAPTER_NUM", "IP_DOG", "AUTH_VERSION", "KEEP_ALIVE_VERSION", "SALT"}:
            self.data["core"][key] = (lambda b: bytes(
                bytearray(b)))(self.data["core"][key])
        return self

    def load(self, file: Path):
        """从 TOML 文件中加载配置

        :param Path file: pathlib.Path 对象，目标 TOML 文件. 字符编码必须是 UTF-8
        """
        content = file.read_text("utf-8")
        return self.loads(content)

    def dumps(self) -> str:
        return toml.dumps(self.data)

    def dump(self, file: Path):
        file.write_text(self.dumps(), encoding="utf-8")

    def __getitem__(self, key):
        return self.data[key]


class SetFilesPathAction(Action):
    """设置 dest 为 Path 对象
    """

    def __call__(self, parser, namespace, values, option_string=None):
        path = (Path(values).absolute(), )  # 需要一个元组
        setattr(namespace, self.dest, path)


def getParser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="Drcom Python Client",
        description="这是 Drcom 的 Python 客户端, 在命令行启动, 停止运行则按 Ctrl+C"
    )
    cmd = parser.add_subparsers(dest="subcmd")
    start = cmd.add_parser("start", description="启动 drcom")
    start.add_argument(
        "-c", "--config",
        dest="config",
        help="指定配置文件 优先级 ./drcom.conf > ~/.config/drcom/drcom.conf > /etc/drcom/drcon.conf",
        required=False,
        metavar="path/to/drcom.conf",
        default=DEFAULT_CONFIG_FILES,
        action=SetFilesPathAction,
    )
    stop = cmd.add_parser("stop", description="停止 drcom")
    log = cmd.add_parser("log", description="显示日志")
    log.add_argument("LEVEL", help="指定浏览的最低日志等级", type=int, default=10, nargs="?")
    log.add_argument("--show-data", help="是否显示原始数据", action="store_true", default=False)
    log.add_argument("--color", help="是否打印彩色输出", action="store_true", default=False)
    analyse = cmd.add_parser("analyse", description="解析抓包，生成配置")
    analyse.add_argument("FILE", help="要解析的抓包文件")
    return parser


def configure() -> DrcomConfig:
    """启动时调用, 返回解析的配置
    """

    arg = getParser().parse_args()
    conf = DrcomConfig()
    for i in arg.config:
        if i.exists():
            file = i
            break
    return conf.load(file)
