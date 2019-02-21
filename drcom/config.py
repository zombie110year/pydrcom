from argparse import SUPPRESS, Action, ArgumentParser
from os import environ
from pathlib import Path
from pkgutil import get_data
from platform import system
from sys import exit

from .utils import Namespace

DEFAULT_CONFIG_FILES = [
    Path("./drcom.conf"),
    Path(
        "{}/.config/drcom/drcom.conf".format(environ["HOME"])
    ),
    Path("/etc/drcom/drcom.conf"),
]
if system() == "Windows":
    DEFAULT_CONFIG_FILES[1] = Path(
        "{}/.config/drcom/drcom.conf".format(environ["USERPROFILE"])
    )

class SetFilesPathAction(Action):
    """设置 dest 为 Path 对象
    """
    def __call__(self, parser, namespace, values, option_string=None):
        path = (Path(values).absolute(), ) # 需要一个元组
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
        file = get_data(__package__, "drcom.conf.temp").decode("utf-8")
        with open("./drcom.conf", "wt", encoding="utf-8") as target:
            target.write(file)
        exit(0)

def getCliArgs():
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
        action=GenerateFileAction,
        default=False
    )
    arg = parser.parse_args()
    return arg

def getConfigFileContent(paths):
    conf = Namespace()

    for file in paths:
        if file.exists():
            script = file.open("rt", encoding="utf-8").read()
            print(
                "使用配置文件 {path}".format(
                    path=str(file.absolute())
                )
            )

            break
        else:
            print(
                "未找到配置文件 {path}".format(
                    path=str(file.absolute())
                )
            )
    else:
        raise FileNotFoundError("找不到配置文件")

    exec(script, {}, conf.__dict__)
    return conf

def configure():

    arg = getCliArgs()
    conf = getConfigFileContent(arg.config)
    return conf
