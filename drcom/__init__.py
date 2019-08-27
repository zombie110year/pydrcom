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
        conf = DrcomConfig()
        conf.load(file)
        app = DrcomApp(conf)
        app.run()
    elif args.subcmd == "log":
        reader = LogReader(args.LEVEL)
        for m in reader.iter():
            print(m.format())
            if input() == "q":
                break
