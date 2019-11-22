from pathlib import Path
from socket import timeout

from .app import DrcomApp
from .config import DrcomConfig
from .config import getParser
from .exceptions import KeepAliveException

def run_drcom(conf: dict):
    while True:
        app = DrcomApp(conf)
        try:
            app.run()
        except timeout:
            app.logger.warn(r"restart caused by timeout", b"")
            continue
        except KeepAliveException as e:
            app.logger.warn(r"restart caused by keepAliveException", e.args[0])
            continue

def main():
    parser = getParser()
    args = parser.parse_args()
    if args.subcmd == "start":
        for i in args.config:
            if i.exists():
                file = i
                break
        else:
            raise FileNotFoundError("找不到可用的配置文件")
        conf = DrcomConfig()
        conf.load(file)
        run_drcom(conf)
