import sqlite3 as s
from os import remove
from pathlib import Path
from tempfile import gettempdir
from time import localtime, mktime, strftime, strptime, time
from binascii import hexlify
from threading import Thread

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
                "data": repr(hexlify(self.data)),
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
    def __init__(self, max_keep: float = None, database: str = None):
        """
        :param float max_keep: 日志最大保存期限，参数应当是 Unix 时间戳
        :param str database: 日志文件路径

        如果留空或者传入 None， max_keep 会使用默认值 7 天，database
        则是 {临时目录}/drcom/log/drcom-log.db
        """
        # 7 天
        self.max_keep = float(604800) if max_keep is None else max_keep
        self.database = str(Path(gettempdir()) / "drcom" / "log" /
                            "drcom-log.log") if database is None else database


class LogWriter(Logger):
    """SQL Logger

    将日志记录在终端中打印，且存储文本文件中。文件存储为 [temp]/drcom/log/drcom-log.log,

    :param int level: 最低日志记录等级，只有高于此等级的事件才会被记录。默认为 10

    各方法的等级依次为：

    .. csv-table::

        verbose,10
        debug,10
        info,20
        warn,30
        error,40
    """

    def __init__(self, level=LEVEL_DEBUG, max_keep=None, database=None):
        super().__init__(max_keep, database)
        self.session = s.connect(self.database)
        self.level = level

    def clean(self):
        """清理超过 7 天的日志
        """
        timedelta = 7 * SECs_ONE_DAY
        c = self.session.cursor()
        c.executescript(f"""DELETE FROM {TABLE_NAME}
        WHERE time < {time() - timedelta};""")
        self.session.commit()

    def record(self, msg: str, data: bytes, level: int):
        if level >= self.level:
            m = Message(time(), level, msg, data)
            print(m.terminal(color=True, data=False))
            with open(self.database, "at", encoding="utf-8") as log:
                print(m.terminal(color=False, data=True), file=log)

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
    def __init__(self, date: str, level: int, max_keep=None, database=None):
        """创建日志查询器

        :param str date: 要查询的日志日期，应当为 %Y-%m-%d 格式的字符串
        :param int level: 要查询的日志等级
        """
        super().__init__(max_keep, database)
        self.session = s.connect(self.database)
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
