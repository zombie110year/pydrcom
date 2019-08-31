#! /usr/bin/env python3
# coding: utf-8
from setuptools import setup, find_packages

PROJECT_NAME = "pydrcom"
VERSION = "3.1.2"
DESCRIPTION = open("docs/_static/description", "rt", encoding="utf-8").read()

setup(
    name=PROJECT_NAME,
    version=VERSION,
    description=DESCRIPTION,
    packages=['drcom', 'drcom.toml'],
    entry_points={
        "console_scripts": [
            "drcom = drcom.__init__:main"
        ]
    },
)
