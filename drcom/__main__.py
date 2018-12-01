from .drcom import Drcom
from .config import configure

def main():
    conf = configure()
    app = Drcom(conf)
    app.run()
