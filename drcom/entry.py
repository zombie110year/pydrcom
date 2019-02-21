from .config import configure
from .drcom import Drcom


def main():
    conf = configure()
    app = Drcom(conf)
    app.run()


if __name__ == "__main__":
    main()
