from .app import DrcomApp
from .config import configure


def main():
    config = configure()
    app = DrcomApp(config)
    app.run()
