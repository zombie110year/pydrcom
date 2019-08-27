import sqlite3 as s
from os import remove
from pathlib import Path
from tempfile import gettempdir
from time import localtime, mktime, strftime, strptime, time

import json

TABLE_NAME = "log"
LEVEL_VERBOSE = 10
LEVEL_DEBUG = 10
LEVEL_INFO = 20
LEVEL_WARN = 30
LEVEL_ERROR = 40


class LogWriter:
    """SQL Logger

    将日志记录在 sqlite3 数据库中。文件存储为 [temp]/drcom/log/*.log。
    每一天都创建一个名称类似于 2019-08-08.log 的数据库文件，在其中创建表 log。

    .. code-block:: sql

        CREATE TABLE log (
            time REAL PRIMARY KEY,
            level INTEGER,
            msg TEXT,
            data BLOB
        );

    :param int level: 最低日志记录等级，只有高于此等级的事件才会被记录。默认为 10

    各方法的等级依次为：

    .. csv-table::

        verbose,10
        debug,10
        info,20
        warn,30
        error,40
    """
    max_keep = float(604800)  # 7 天

    def __init__(self, level=LEVEL_DEBUG):
        self.database = Path
        self.session = s.Connection
        self.level = level

        # 每天都创建一个新的数据库
        tempdir = Path(gettempdir()) / "drcom" / "log"
        now = time()
        self.database = tempdir / \
            f"""{strftime("%Y-%m-%d", localtime(now))}.log"""
        self.session = s.connect(str(self.database.absolute()))
        c = self.session.cursor()
        table_exists = ('table', 'log') in c.execute(
            f"SELECT type, name FROM sqlite_master WHERE name='{TABLE_NAME}'")
        if not table_exists:
            c.executescript(
                f"""CREATE TABLE {TABLE_NAME} (time REAL PRIMARY KEY, level INTEGER, msg TEXT, data BLOB);""")
            self.session.commit()
        # 检查旧数据库, 并清除 7 天前的数据库
        for i in tempdir.glob("*.log"):
            that = mktime(strptime("%Y-%m-%d", i.stem))
            if now - that > self.max_keep:
                remove(str(i.absolute()))

    def record(self, msg: str, data: bytes, level: int):
        if level >= self.level:
            m = Message(time(), level, msg, data)
            c = self.session.cursor()
            m.store(c)
            self.session.commit()

    def verbose(self, msg: str, data: bytes):
        self.record(msg, data, LEVEL_VERBOSE)

    def debug(self, msg: str, data: bytes):
        self.record(msg, data, LEVEL_DEBUG)

    def info(self, msg: str, data: bytes):
        self.record(msg, data, LEVEL_INFO)

    def warn(self, msg: str, data: bytes):
        self.record(msg, data, LEVEL_WARN)

    def error(self, msg: str, data: bytes):
        self.record(msg, data, LEVEL_ERROR)


class LogReader:
    pass


class Message:
    def __init__(self, time: float, level: int, msg: str, data: bytes):
        self.time = time
        self.level = level
        self.msg = msg
        self.data = data

    @property
    def sql(self) -> str:
        return f"""INSERT INTO {TABLE_NAME} (time, level, msg, data)
        VALUES (?, ?, ?, ?);"""

    def store(self, cursor: s.Cursor):
        cursor.execute(self.sql, (self.time, self.level, self.msg, self.data))
