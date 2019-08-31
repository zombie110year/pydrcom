from pathlib import Path

from .analyse import analysePcapng
from .app import DrcomApp
from .config import DrcomConfig, getParser
from .log import LogReader


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
        app = DrcomApp(conf)
        app.run()
    elif args.subcmd == "log":
        reader = LogReader(args.date, args.LEVEL)
        if args.to_csv:
            reader.to_csv(Path("today-log.csv"))
        else:
            for m in reader.iter():
                print(m.terminal(color=args.color, data=args.show_data), end="")
                if input() == "q":
                    break
    elif args.subcmd == "analyse":
        path = Path(args.FILE)
        conf = analysePcapng(path)
        conf.dump(Path("drcom.toml"))
        print("file saved at ./drcom.toml")
