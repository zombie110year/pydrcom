import binascii
import os
import struct
import sys
import time
from hashlib import md5


class Namespace:
    pass


class ChallengeException(Exception):
    def __init__(self):
        pass


class LoginException(Exception):
    def __init__(self):
        pass


class RuntimeCounter:
    """记录运行次数, 若达到限制则终止

    :param int max: 最大运行次数

    .. method:: clear()

        清空计数器
    """

    def __init__(self, max=5):
        self.__max = max
        self.__counter = 0

    def __repr__(self):
        return "RuntimeCounter<{}/{}>".format(
            self.__counter,
            self.__max
        )

    def __call__(self, action=None, args=(), kwargs={}):
        """当 RuntimeCounter 的计数超过限度时,
        调用 action, args, 和 kwargs 是传给 action 的参数.

        :param action: 一个函数
        :param list args: 传递给 action 的参数列表
        :param dict kwargs: 传递给 action 的命名参数列表
        """
        if self.__counter >= self.__max:
            if callable(action):
                action(*args, **kwargs)
            sys.exit(-1)
        else:
            self.__counter += 1

    def clear(self):
        self.__counter = 0


def md5sum(x: bytes) -> bytes:
    """得到输入字节的 md5 值

    >>> md5sum(b'\x03\x01')
    b' \xf9\xaa|\x18\x9a\xf6\xe6A\xa46i\xbe\xbf\x1cc'
    """
    m = md5()
    m.update(x)
    return m.digest()


def dump(n: int) -> bytes:
    """将整数转换为对应的字节

    >>> dump(1)
    b'\x01'
    >>> dump(0x16)
    b'\x16'
    >>> dump(0xffffffff)
    b'\xff\xff\xff'
    """
    s = '%x' % n
    if len(s) & 1:  # 奇数
        s = '0' + s
    return binascii.unhexlify(bytes(s, 'ascii'))


def ror(md5sum: bytes, pwd: str) -> str:
    """ror 加密

    :param bytes md5sum: md5 检验和 16 字节
    :param str pwd: Drcom 用户的密码
    """
    result = []
    for i in range(len(pwd)):
        x = ord(md5sum[i]) ^ ord(pwd[i])
        result.append(struct.pack("B", ((x << 3) & 0xff) + (x >> 5)))
    return ''.join(result)


def checksum(bytes_: bytes) -> bytes:
    """checksum 验证，引用 self.mac
    """
    resualt = 1234
    for i in [x*4 for x in range(0, -(-len(bytes_)//4))]:
        resualt ^= int(
            binascii.hexlify(bytes_[i:i+4].ljust(4, b'\x00')[::-1]), 16
        )

    resualt = (1968 * resualt) & 0xffffffff
    return struct.pack('<I', resualt)


def daemon():
    """适用于 Linux 系统
    """
    with open('/var/run/drcom.pid', 'w') as file:
        file.write(str(os.getpid()))


def getIP() -> str:
    """更通用的获取 IP 地址的方法:
        通过构造一个连接向非本地的 UDP 包, 获取自身 IP 信息

        并不会真实发包.
    """
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip, port = s.getsockname()
    s.close()
    return ip


def getMacAdress() -> int:
    """获取网卡 mac 地址

    :rtype: int
    """
    import uuid
    node = uuid.getnode()
    return node


def showBytes(b: bytes) -> bytes:
    """将字节转换成可读的字符串样式

    >>> showBytes(b'\x01')
    b'01'
    """
    return binascii.hexlify(b)[2:][:-1]
