from hashlib import md5
import struct
import time
import sys
import os
import platform
import random
import binascii
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
