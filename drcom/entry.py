import logging
from platform import platform

from .config import configure
from .drcom import Drcom
from .utils import daemon


def main():
    if platform() == "Linux":
        daemon()

    conf = configure()

    logger = logging.getLogger("drcom")
    logger.setLevel(conf.LOG_LEVEL)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt="[{levelname:^9}] {asctime} {message}",
        datefmt="%Y-%m-%d %H:%M:%S",
        style="{"
    )
    console.setFormatter(formatter)
    logger.addHandler(console)

    app = Drcom(conf, logger)
    try:
        app.run()
    except KeyboardInterrupt:
        app.logout()
