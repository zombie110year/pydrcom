from .config import configure, getConfigFileContent
from .drcom import Drcom


def _main(conf_path):
    conf = getConfigFileContent(conf_path)
    app = Drcom(conf)
    return app


def main():
    conf = configure()
    app = Drcom(conf)
    app.run()


if __name__ == "__main__":
    main()
