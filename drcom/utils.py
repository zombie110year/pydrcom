import binascii
import os
import platform
import random
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


def log(*args, **kwargs):
    print(
        ' '.join(args)
    )


def md5sum(x):
    m = md5()
    m.update(x)
    return m.digest()


def dump(n):
    s = '%x' % n
    if len(s) & 1:  # 奇数
        s = '0' + s
    return binascii.unhexlify(bytes(s, 'ascii'))


def ror(md5sum, pwd):
    result = []
    for i in range(len(pwd)):
        x = ord(md5sum[i]) ^ ord(pwd[i])
        result.append(struct.pack("B", ((x << 3) & 0xff) + (x >> 5)))
    return ''.join(result)


def checksum(bytes_):
    resualt = 1234
    for i in [x*4 for x in range(0, -(-len(bytes_)//4))]:
        resualt ^= int(
            binascii.hexlify(bytes_[i:i+4].ljust(4, b'\x00')[::-1]), 16
        )

    resualt = (1968 * resualt) & 0xffffffff
    return struct.pack('<I', resualt)


def daemon():
    with open('/var/run/drcom.pid', 'w') as file:
        file.write(str(os.getpid()))

def getIP(ifname):
    """获取目标网卡所占的 IP 地址
    Linux 下可用.

    原理可以看 https://bitmingw.com/2018/05/06/get-ip-address-of-network-interface-in-python/

    :param str ifname: 目标网卡的命名, 可以使用 ifconfig 查看, 例如 ``eth0``.
    """
    import socket
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(
        fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('40s', ifname[:15].encode("utf-8"))
        )[20:24]
    )
