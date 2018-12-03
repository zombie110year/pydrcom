from setuptools import setup, find_packages

PROJECT_NAME = "PyDrcom"
VERSION = "1.0.0"
DESCRIPTION = open("docs/description", "rt", encoding="utf-8").read()

setup(
    name=PROJECT_NAME,
    version=VERSION,
    description=DESCRIPTION,
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "drcom = drcom.__main__:main"
        ]
    },
)
