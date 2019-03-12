#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import logging
import platform
import random
import re
import socket
import struct
import sys
import time

from .utils import (ChallengeException, LoginException, RuntimeCounter,
                    checksum, daemon, dump, getIP, getMacAdress, md5sum, ror)


class Drcom:
    """
    Drcom 客户端运行所需要的一切

    :param conf: 处理后的配置项. 将从 conf 的属性读取配置, 例如 conf.username 等.
    :type conf: :class:`Namespace`
    """

    def setConf(self, conf):

        self.username = conf.username
        self.password = conf.password
        self.server = conf.server
        self.dns = conf.dns
        self.dhcp_server = conf.dhcp_server
        self.host_name = conf.host_name
        self.host_os = conf.host_os
        self.host_ip = getIP()          # 自动获取 IP 地址
        self.mac = getMacAdress()       # 自动获取 Mac 地址
        self.bind_ip = "0.0.0.0"        # 必须绑定在 0.0.0.0
        self.port = conf.port
        self.nic_name = conf.nic_name
        self.LOG_FILE = None
        self.LOG_LEVEL = conf.LOG_LEVEL
        self.CONTROL_CHECK_STATUS = conf.CONTROL_CHECK_STATUS
        self.ADAPTER_NUM = conf.ADAPTER_NUM
        self.KEEP_ALIVE_VERSION = conf.KEEP_ALIVE_VERSION
        self.AUTH_VERSION = conf.AUTH_VERSION
        self.IPDOG = conf.IPDOG
        self.SALT = conf.SALT
        self.ror_version = conf.ror_version

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(60000, 65535):
            try:
                self.bind_port = i
                self.socket.bind((self.bind_ip, self.bind_port))
                break
            except OSError: # errno 98 address already in use
                continue

        logging.basicConfig(
            level=getattr(logging, self.LOG_LEVEL, logging.DEBUG),
            stream=sys.stderr,
            format="{levelname}: {message}",
            style="{",
        )

        self.socket.settimeout(3)
        # 将在 login 时被赋值, 在 logout 时使用
        self.AUTH_INFO = None


    def __init__(self, conf):
        self.setConf(conf)
        self.counter = RuntimeCounter()

    def challenge(self, rand_num):
        while True:
            pack = struct.pack("<H", int(rand_num) % 0xffff)
            self.socket.sendto(
                b"\x01\x02" + pack + b"\x09" + b"\x00"*15,
                (self.server, self.port)
            )
            try:
                data, address = self.socket.recvfrom(1024)
                logging.info('[challenge] recv')
                logging.debug(str(binascii.hexlify(data))[2:][:-1])
                self.counter.clear()
            except socket.timeout:
                logging.warning('[challenge] timeout, retrying...')
                self.counter()
                continue

            if address == (self.server, self.port):
                break

            logging.info('[DEBUG] challenge')
            logging.debug(str(binascii.hexlify(data))[2:][:-1])

            if data[:1] != b'\x02':     # 对字节不要 data[0]
                raise ChallengeException()

            logging.info('[challenge] challenge packet sent.')

        return data[4:8]

    def makeKeepAlivePackage(self, num, tail, type_=1, first=False):
        data = b''

        data += b'\x07' + bytes([num]) + b'\x28\x00\x0B' + bytes([type_])

        if first:
            data += b'\x0f\x27'
        else:
            data += self.KEEP_ALIVE_VERSION
        data += b'\x2F\x12' + b'\x00'*6
        data += tail
        data += b'\x00'*4

        if type_ == 3:
            foo = b''.join(
                [bytes([int(i)]) for i in self.host_ip.split('.')]
            )
            crc = b'\x00'*4
            data += crc + foo + b'\x00'*8
        else:
            data += b'\x00'*16

        return data

    def mkpkt(self):

        data = b''

        data += b'\x03\x01\x00' + bytes([len(self.username) + 20])
        data += md5sum(b'\x03\x01' + self.SALT + self.password.encode())
        data += (self.username.encode() + b'\x00'*36)[:36]
        data += self.CONTROL_CHECK_STATUS
        data += self.ADAPTER_NUM
        data += dump(
                    int(
                        binascii.hexlify(data[4:10]),
                        base=16
                    ) ^ self.mac
                )[-6:]
        data += md5sum(b'\x01' + self.password.encode() + self.SALT + b'\x00'*4)
        data += b'\x01'
        data += b''.join(
                    [bytes([int(i)]) for i in self.host_ip.split('.')]
                )
        data += b'\x00'*12
        data += md5sum(data + b'\x14\x00\x07\x0B')[:8]
        data += self.IPDOG
        data += b'\x00'*4
        data += (self.host_name.encode() + b'\x00'*32)[:32]
        data += b''.join(
                    [bytes([int(i)]) for i in self.dns.split('.')]
                )

        data += b''.join(
                    [bytes([int(i)]) for i in self.dhcp_server.split('.')]
                )
        data += b'\x00'*12
        data += b'\x94\x00\x00\x00'
        data += b'\x05\x00\x00\x00'
        data += b'\x01\x00\x00\x00'
        data += b'\x28\x0A\x00\x00'
        data += b'\x02\x00\x00\x00'
        data += (self.host_os.encode() + 32*b'\x00')[:32]
        data += b'\x00'*96
        data += self.AUTH_VERSION
        if self.ror_version:
            data += b'\x00'
            data += bytes([len(self.password)])
            data += ror(md5sum(b'\x03\x01' + self.SALT + self.password), self.password)

        data += b'\x02\x0c'
        data += checksum(
            data + b'\x01\x26\x07\x11\x00\x00' + dump(self.mac)
        )

        data += b'\x00\x00\xe9\x13'

        logging.info('[mkpkt]')
        logging.debug(str(binascii.hexlify(data))[2:][:-1])
        return data

    def keepAlive1(self, tail):
        data = b''
        foo = struct.pack("!H", int(time.time()) % 0xffff)
        data += b'\xff' + md5sum(
                b'\x03\x01' + self.SALT + self.password.encode()
            ) + b'\x00\x00\x00'

        data += tail
        data += foo + b'\x00\x00\x00\x00'

        logging.info('[keepAlive1] send')
        logging.debug(str(binascii.hexlify(data))[2:][:-1])

        self.socket.sendto(data, (self.server, self.port))

        while True:

            try:
                data_, address = self.socket.recvfrom(1024)
            except socket.timeout:
                self.socket.sendto(data, (self.server, self.port))
                continue

            if data_[:1] == b'\x07':
                break
            else:
                logging.info('[keepAlive1] recv/unexpected')
                logging.debug(str((binascii.hexlify(data))[2:][:-1]))

        logging.info('[keepAlive1] recv')
        logging.debug(str(binascii.hexlify(data))[2:][:-1])

    def keepAlive2(self, package_tail):
        tail = None
        package = None
        svr_num = 0
        rand_num = random.randint(0, 0xffff) + random.randint(1, 10)
        package = self.makeKeepAlivePackage(
            num=svr_num,
            tail=b'\x00'*4,
            type_=1,
            first=True
        )

        while True:
            self.socket.sendto(package, (self.server, self.port))
            logging.info('[keepAlive2] send1')
            logging.debug(str(binascii.hexlify(package))[2:][:-1])

            data, address = self.socket.recvfrom(1024)
            logging.info('[keepAlive2] recv1')
            logging.debug(str(binascii.hexlify(data))[2:][:-1])

            if (
                data.startswith(b'\x07\x00\x28\x00') or
                data.startswith(b'\x07' + bytes([svr_num]) + b'\x28\x00')
            ):
                break
            elif data[:1] == b'\x07' and data[2:3] == b'\x10':
                logging.info('[keepAlive2] recv file, resending..')
                svr_num += 1
                break
            else:
                logging.info("[keepAlive2] recv1/unexpected")
                logging.debug(str(binascii.hexlify(data))[2:][:-1])

        rand_num += random.randint(1, 10)
        package = self.makeKeepAlivePackage(
            num=svr_num,
            tail=b'\x00'*4,
            type_=1
        )
        self.socket.sendto(package, (self.server, self.port))
        logging.info('[keepAlive2] send2')
        logging.debug(str(binascii.hexlify(package))[2:][:-1])

        while True:
            data, address = self.socket.recvfrom(1024)
            if data[:1] == b'\x07':
                svr_num += 1
                self.counter.clear()
                break
            else:
                self.counter()
                logging.info('[keepAlive2] recv2/unexpected')
                logging.debug(str(binascii.hexlify(data))[2:][:-1])

        logging.info('[keepAlive2] recv2')
        logging.debug(str(binascii.hexlify(data))[2:][:-1])

        tail = data[16:20]

        rand_num += random.randint(1, 10)

        package = self.makeKeepAlivePackage(
            num=svr_num,
            tail=tail,
            type_=3
        )

        self.socket.sendto(package, (self.server, self.port))

        while True:
            data, address = self.socket.recvfrom(1024)

            if data[:1] == b'\x07':
                svr_num += 1
                self.counter.clear()
                break
            else:
                logging.info('[keepAlive2] recv3/unexpected')
                logging.debug(str(binascii.hexlify(data))[2:][:-1])
                self.counter()

        logging.info('[keepAlive2] recv3')
        logging.debug(str(binascii.hexlify(data))[2:][:-1])

        tail = data[16:20]

        logging.info("[keepAlive2] keepAlive2 loop was in daemon.")

        svr_num_copy = svr_num

        # 稳定状态
        while True:
            time.sleep(20)
            try:
                self.keepAlive1(package_tail)
                rand_num += random.randint(1, 10)
                package = self.makeKeepAlivePackage(
                    num=svr_num_copy,
                    tail=tail,
                    type_=1
                )

                self.socket.sendto(package, (self.server, self.port))
                logging.info('[keepAlive2] send')
                logging.debug(str(svr_num_copy))
                logging.debug(str(binascii.hexlify(package))[2:][:-1])

                try:
                    data, address = self.socket.recvfrom(1024)
                except socket.timeout:
                    self.counter()

                self.counter.clear()
                logging.info('[keepAlive2] recv')
                logging.debug(str(binascii.hexlify(data))[2:][:-1])
                tail = data[16:20]
                rand_num += random.randint(1, 10)

                package = self.makeKeepAlivePackage(
                    num=svr_num_copy+1,
                    tail=tail,
                    type_=3,
                )

                self.socket.sendto(package, (self.server, self.port))
                logging.info('[keepAlive2] send')
                logging.debug(str(svr_num_copy+1))
                logging.debug(str(binascii.hexlify(package))[2:][:-1])

                try:
                    data, address = self.socket.recvfrom(1024)
                except socket.timeout:
                    self.counter()
                self.counter.clear()

                logging.info('[keepAlive2] recv')
                logging.debug(str(binascii.hexlify(data))[2:][:-1])
                tail = data[16:20]

                svr_num_copy = (svr_num_copy + 2) % 127
            except KeyboardInterrupt:
                self.logout()

    def login(self):
        i = 0
        while True:
            self.SALT = self.challenge(time.time()+random.randint(0xf, 0xff))

            packet = self.mkpkt()

            self.socket.sendto(packet, (self.server, self.port))
            logging.info('[login] send')
            logging.debug(str(binascii.hexlify(packet))[2:][:-1])

            try:
                data, address = self.socket.recvfrom(1024)
            except socket.timeout:
                continue

            logging.info('[login] recv')
            logging.debug(str(binascii.hexlify(data))[2:][:-1])
            logging.info('[login] packet sent.')

            if address == (self.server, self.port):
                if data[:1] == b'\x04':
                    logging.info('[login] loged in')
                    self.AUTH_INFO = data[23:39]
                    break
                else:
                    logging.warning('[login] login failed.')
                    time.sleep(30)
                    continue
            else:
                if i >= 5:
                    logging.error('[login] exception occured.')
                    sys.exit(1)
        logging.info('[login] login sent')
        return data[23:39]

    def logout(self):
        salt = self.challenge(time.time()+random.randint(0xF, 0xFF))
        data = b''
        if salt:
            data += b'\x06\x01\x00' + bytes([len(self.username) + 20])
            data += md5sum(b'\x03\x01' + salt + self.password.encode())
            data += (self.username.encode() + 36*b'\x00')[:36]
            data += self.CONTROL_CHECK_STATUS
            data += self.ADAPTER_NUM
            data += dump(
                    int(binascii.hexlify(b''.join(data[4:10])), 16) ^ self.mac
                )[-6:]

            data += self.AUTH_INFO

            self.socket.sendto(data, (self.server, self.port))
            data, address = self.socket.recvfrom(1024)
            if data[:1] == b'\x04':
                logging.info('[logout] logouted.')
                exit(0)

    def emptySocketBuffer(self):
        logging.info('starting to empty socket buffer')
        while True:
            try:
                data, address = self.socket.recvfrom(1024)
            except socket.timeout:
                logging.info('recived sth unexpected')
                logging.debug(data)
                break
        logging.info('Emptied')

    def run(self):
        if platform.platform() == "Linux":
            daemon()
        logging.info(
            """
            auth svr:  {server}
            username:  {username}
            password:  {password}
            mac:       0x{mac:x}
            host_ip:   {ip}
            bind_port: {bind_port}
            """.format(
                server=self.server,
                username=self.username,
                password='*'*len(self.password),
                mac=self.mac,
                ip=self.host_ip,
                bind_port=self.bind_port,
            )
        )
        while True:
            try:
                package_tail = self.login()
            except LoginException:
                time.sleep(3)
                continue
            logging.debug('package_tail')
            logging.debug(str(binascii.hexlify(package_tail))[2:][:-1])
            self.emptySocketBuffer()
            self.keepAlive1(package_tail)
            self.keepAlive2(package_tail)
