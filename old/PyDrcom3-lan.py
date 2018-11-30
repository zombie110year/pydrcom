import socket
import struct
import time
import sys
import random
import os
import hashlib
import binascii

# CONFIG
server = "10.254.7.4"
pppoe_flag = b'\x2a'
keep_alive2_flag = b'\xdc'
# ENDCONFIG

host_ip = server
LOG_PATH = "./drcom_client.log"

def log(*args, **kwargs):
    s = ' '.join(args)
    print(s)

def dump(n):
    s = '%x' % n
    if len(s) & 1:
        s = '0' + s
    return binascii.unhexlify(bytes(s, 'ascii'))

def genCRC(data, encrypt_type):
    DRCOM_DIAL_EXT_PROTO_CRC_INIT = 20000711
    ret = ''
    if encrypt_type == 0:
        # 无加密
        return (struct.pack('<I', DRCOM_DIAL_EXT_PROTO_CRC_INIT) + struct.pack('<I', 126), False)

