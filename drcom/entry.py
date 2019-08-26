import logging
from platform import platform

from .config import configure
from .drcom import Drcom
from .utils import daemon


def main():
    if platform() == "Linux":
        daemon()

    conf = configure()
    app = Drcom(conf, logger)
    try:
        app.run()
    except KeyboardInterrupt:
        app.logout()
