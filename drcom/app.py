from .config import DrcomConfig
from .context import DrcomContext
import socket as s

from .utils import ChallengeException
import time
import random
import struct


class DrcomApp:
    """Drcom 应用程序

    提供 Drcom 客户端的一切功能, 包括:

    1. 启动 Drcom
    2. 日志记录
    3. 错误处理
    4. 管理配置
    5. 分析抓包并生成配置
    """

    def __init__(self, config: DrcomConfig):
        """根据 DrcomConfig 实例化应用程序
        """
        self.application = config["application"]
        self.drcom = config["drcom"]
        self.core = config["core"]

        self.context = self.initContext()
        # IPv4, UDP
        self.socket = s.socket(s.AF_INET, s.SOCK_DGRAM)
        self.socket.settimeout(10)
        for i in range(60000, 0x10000):
            try:
                self.socket.bind((self.application["bind_ip"], i))
                break
            except OSError:
                # errno 98 address already in use
                continue
        else:
            raise Exception("从 60000 到 65536 间端口已耗尽")

    def run(self):
        """开始运行"""
        self.login()
        self.emptySocketBuffer()
        self.keepAlive()

    def initContext(self) -> DrcomContext:
        dc = DrcomContext(
            server=self.drcom["server"],
            username=self.drcom["username"],
            password=self.drcom["password"],
            mac=self.drcom["mac"],
            host_ip=self.drcom["host_ip"],
            host_name=self.drcom["host_name"],
            host_os=self.drcom["host_os"],
            dhcp=self.drcom["dhcp"],
            dns=self.drcom["dns"],
            CONTROL_CHECK_STATUS=self.core["CONTROL_CHECK_STATUS"],
            ADAPTER_NUM=self.core["ADAPTER_NUM"],
            IP_DOG=self.core["IP_DOG"],
            AUTH_VERSION=self.core["AUTH_VERSION"],
            SALT=self.core["SALT"],
            ROR_VERSION=self.core["ROR_VERSION"],
        )
        return dc

    def login(self):
        """登录

        调用函数

        -   :meth:`challenge`
        -   :meth:`sendLogin`
        """
        while True:
            self.challenge()
            self.sendLogin()

    def challenge(self):
        """尝试连接

        读取属性

        -   drcom.server
        -   drcom.server_port

        修改属性

        -   context.SALT
        """
        rand = time.time() + random.randint(0xf, 0xff)
        while True:
            pack = struct.pack("<H", int(rand) % 0xffff)
            self.socket.sendto(
                b'\x01\x02' + pack + b'\x09' + b'\x00' * 15,
                (self.drcom["server"], self.drcom["server_port"])
            )
            try:
                data, address = self.socket.recvfrom(1024)
            except s.timeout:
                continue
            if address == (self.drcom["server"], self.drcom["server_port"]):
                break
            if data[:1] != b'\x02':
                raise ChallengeException()

        self.context.SALT = data[4:8]
