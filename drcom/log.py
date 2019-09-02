import sqlite3 as s
from os import remove
from pathlib import Path
from tempfile import gettempdir
from time import localtime, mktime, strftime, strptime, time

import json

TABLE_NAME = "log"
# 一天的秒数
SECs_ONE_DAY = 86400.0
LEVEL_VERBOSE = 0
LEVEL_DEBUG = 10
LEVEL_INFO = 20
LEVEL_WARN = 30
LEVEL_ERROR = 40


class Message:
    COLORS = {
        LEVEL_VERBOSE: 0,
        LEVEL_DEBUG: 2,
        LEVEL_INFO: 0,
        LEVEL_WARN: 3,
        LEVEL_ERROR: 1,
    }

    CHARS = {
        LEVEL_VERBOSE: "V",
        LEVEL_DEBUG: "D",
        LEVEL_INFO: "I",
        LEVEL_WARN: "W",
        LEVEL_ERROR: "E",
    }

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

    def terminal(self, **kw):
        """格式化字符串, 输出至终端的格式

        :param bool data: 是否显示原始字节
        :param bool color: 是否返回 ASCII 着色
        """
        string = "{lco} {time}:: {msg}"
        cmap = {
            "msg": self.msg,
            "time": strftime("%Y-%m-%d %H:%M:%S", localtime(self.time)),
            "lco": self.CHARS[self.level],
        }
        if kw.get("data", False):
            string += " {dco}{data}{co0}"
            cmap.update({
                "dco": "",
                "data": repr(self.data),
                "co0": "",
            })
        if kw.get("color", False):
            cmap.update({
                "lco": f"\x1b[3{self.COLORS[self.level]}m{self.CHARS[self.level]}\x1b[0m",
                "dco": f"\x1b[32m",
                "co0": "\x1b[0m"
            })

        return string.format(**cmap)

    def to_csv(self):
        """格式化为 csv 格式"""
        string = "{level:2},{time},{msg},{data}"
        return string.format(
            level=self.level,
            time=strftime("%Y-%m-%d %H:%M:%S", localtime(self.time)),
            msg=self.msg,
            data=repr(self.data),
        )


class Logger:
    max_keep = float(604800)  # 7 天
    database = str(Path(gettempdir()) / "drcom" / "log" / "drcom-log.db")


class LogWriter(Logger):
    """SQL Logger

    将日志记录在 sqlite3 数据库中。文件存储为 [temp]/drcom/log/drcom-log.db,
    表名为 log.

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

    def __init__(self, level=LEVEL_DEBUG):
        self.session = s.connect(self.database)
        self.level = level

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


class LogReader(Logger):
    def __init__(self, date: str, level):
        """创建日志查询器

        :param str date: 要查询的日志日期，应当为 %Y-%m-%d 格式的字符串
        :param int level: 要查询的日志等级
        """
        self.session = s.Connection(self.database)
        self.level = level
        self.date = mktime(strptime(date, "%Y-%m-%d"))

    def iter(self) -> Message:
        """按时间顺序从晚到早
        """
        c = self.session.cursor()
        result = c.execute(
            f"""SELECT time, level, msg, data FROM {TABLE_NAME}
                WHERE level>={self.level} AND time >= {self.date} AND time <= {self.date + SECs_ONE_DAY};""")
        for time, level, msg, data in result:
            yield Message(time, level, msg, data)

    def to_csv(self, path: Path):
        """将目标日期日志保存至文件"""
        with path.open("wt", encoding="utf-8") as file:
            file.write("level,time,msg,data\n")
            for m in self.iter():
                file.write(m.to_csv())
                file.write("\n")
