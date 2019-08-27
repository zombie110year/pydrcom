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
from .utils import Namespace

if system() == "Windows":
    DEFAULT_CONFIG_FILES = [
        Path("./drcom.conf"),
        Path(
            "{}/.config/drcom/drcom.conf".format(environ["USERPROFILE"])
        ),
        Path("/etc/drcom/drcom.conf"),
    ]
else:
    DEFAULT_CONFIG_FILES = [
        Path("./drcom.conf"),
        Path(
            "{}/.config/drcom/drcom.conf".format(environ["HOME"])
        ),
        Path("/etc/drcom/drcom.conf"),
    ]


class DrcomConfig:
    """DrcomConfig

    DrcomApp 使用的配置文件
    """

    def __init__(self):
        self.data = {
            "application": {
                "logging": 10,              # int
            },
            "drcom": {
                "server": "认证服务器",     # str
                "username": "校园网账号",   # str
                "password": "校园网密码",   # str
                "mac": 0x0,                 # int
                "host_ip": "192.168.0.1",   # str
                "host_name": "F**K DRCOM",  # str
                "host_os": "DRCOM F**KER",  # str
                "dhcp": "0.0.0.0",          # str
                "dns": "8.8.8.8",           # str
            },
            "core": {
                "BIND_IP": "0.0.0.0",   # 客户端必须监听网卡上所有接口
                "SERVER_PORT": 61440,   # 认证服务器端口
                "CONTROL_CHECK_STATUS": b"",    # bytes
                "ADAPTER_NUM": b"",             # bytes
                "IP_DOG": b"",                  # bytes
                "AUTH_VERSION": b"",            # bytes
                "KEEP_ALIVE_VERSION": b"",      # bytes
                "SALT": b"",                    # bytes
                "ROR_VERSION": b"",             # bytes
            }
        }

    def loads(self, string: str):
        """从 TOML 格式的字符串中加载配置
        """
        self.data = toml.loads(string)
        for key in self.data["core"]:
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


class SetFilesPathAction(Action):
    """设置 dest 为 Path 对象
    """

    def __call__(self, parser, namespace, values, option_string=None):
        path = (Path(values).absolute(), )  # 需要一个元组
        setattr(namespace, self.dest, path)


class GenerateFileAction(Action):
    """生成文件后退出
    """

    def __init__(self,
                 option_strings,
                 dest=SUPPRESS,
                 default=SUPPRESS,
                 help=None):
        super(GenerateFileAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        conf = DrcomConfig()
        target_file = Path("./drcom.conf")
        conf.dump(target_file)
        print("配置文件生成于 {}".format(target_file.absolute()))
        parser.exit()


def getParser():
    parser = ArgumentParser(
        prog="Drcom Python Client",
        description="这是 Drcom 的 Python 客户端, 在命令行启动, 停止运行则按 Ctrl+C"
    )
    parser.add_argument(
        "-c", "--config",
        dest="config",
        help="指定配置文件 优先级 ./drcom.conf > ~/.config/drcom/drcom.conf > /etc/drcom/drcon.conf",
        required=False,
        metavar="path/to/drcom.conf",
        default=DEFAULT_CONFIG_FILES,
        action=SetFilesPathAction,
    )
    parser.add_argument(
        "--generate-config",
        help="在当前目录下生成配置文件模板",
        action=GenerateFileAction
    )
    return parser


def configure():
    """启动时调用, 返回解析的配置
    """

    arg = getParser().parse_args()
    conf = DrcomConfig()
    return conf.load(arg.config)
