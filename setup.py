#! /usr/bin/env python3
# coding: utf-8
from setuptools import setup, find_packages

PROJECT_NAME = "pydrcom"
VERSION = "1.0.1"
DESCRIPTION = open("docs/description", "rt", encoding="utf-8").read()

setup(
    name=PROJECT_NAME,
    version=VERSION,
    description=DESCRIPTION,
    packages=['drcom'],
    entry_points={
        "console_scripts": [
            "drcom = drcom.entry:main"
        ]
    },
)
