from io import StringIO
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
        reader = LogReader(args.DATE, args.level)
        if args.to_csv:
            reader.to_csv(Path("today-log.csv"))
        else:
            buffer = StringIO()
            for m in reader.iter():
                buffer.write(m.terminal(color=args.color, data=args.show_data))
                buffer.write("\n")
            buffer.seek(0)
            print(buffer.read())
    elif args.subcmd == "analyse":
        path = Path(args.FILE)
        conf = analysePcapng(path)
        conf.dump(Path("drcom.toml"))
        print("file saved at ./drcom.toml")
