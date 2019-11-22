from pathlib import Path

from .config import DrcomConfig
from .config import getParser


def run_drcom(conf: dict):
    while True:
        app = DrcomApp(conf)
        app.run()

def main():
    parser = getParser()
    args = parser.parse_args()
    if args.subcmd == "start":
        from .app import DrcomApp
        for i in args.config:
            if i.exists():
                file = i
                break
        else:
            raise FileNotFoundError("找不到可用的配置文件")
        conf = DrcomConfig()
        conf.load(file)
        run_drcom(conf)
