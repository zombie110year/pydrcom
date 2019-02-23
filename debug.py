#! /usr/bin/env python3
# coding: utf-8

from drcom.entry import main, _main

app = _main("debug/drcom.conf")
app.run()
