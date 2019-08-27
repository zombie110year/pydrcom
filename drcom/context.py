#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import platform
import random
import re
import socket
import struct
import sys
import time

from .utils import (checksum, daemon, dump, getIP, getMacAdress, md5sum, ror,
                    showBytes)


class DrcomContext:
    """Drcom 运行时上下文

    只做纯粹的发包, 解包工作.

    初始化上下文
    ============

    :param str server:      Drcom 认证服务器的地址
    :param str username:    校园网账号
    :param str password:    校园网密码
    :param int mac:         本机 mac 地址
    :param str host_ip:     本机 IP 地址
    :param str host_name:   本机主机名
    :param str host_os:     本机操作系统名
    :param str dhcp:        dhcp 服务器地址
    :param str dns:         dns 服务器地址
    :param bytes CONTROL_CHECK_STATUS:
    :param bytes ADAPTER_NUM:
    :param bytes IP_DOG:
    :param bytes AUTH_VERSION:
    :param bytes SALT:
    :param bytes KEEP_ALIVE_VERSION:
    :param bytes ROR_VERSION:
    """

    def __init__(self,
                 server: str,
                 username: str,
                 password: str,
                 mac: int,
                 host_ip: str,
                 host_name: str,
                 host_os: str,
                 dhcp: str,
                 dns: str,
                 CONTROL_CHECK_STATUS: bytes,
                 ADAPTER_NUM: bytes,
                 IP_DOG: bytes,
                 AUTH_VERSION: bytes,
                 SALT: bytes,
                 KEEP_ALIVE_VERSION: bytes,
                 ROR_VERSION: bytes,):
        """初始化上下文

        :param str server:      Drcom 认证服务器的地址
        :param str username:    校园网账号
        :param str password:    校园网密码
        :param int mac:         本机 mac 地址
        :param str host_ip:     本机 IP 地址
        :param str host_name:   本机主机名
        :param str host_os:     本机操作系统名
        :param str dhcp:        dhcp 服务器地址
        :param str dns:         dns 服务器地址
        :param bytes CONTROL_CHECK_STATUS:
        :param bytes ADAPTER_NUM:
        :param bytes IP_DOG:
        :param bytes AUTH_VERSION:
        :param bytes SALT:
        :param bytes KEEP_ALIVE_VERSION:
        :param bytes ROR_VERSION:
        """
        self.server = server
        self.username = username
        self.password = password
        self.mac = mac
        self.host_ip = host_ip
        self.host_name = host_name
        self.host_os = host_os
        self.dhcp = dhcp
        self.dns = dns
        self.CONTROL_CHECK_STATUS = CONTROL_CHECK_STATUS
        self.ADAPTER_NUM = ADAPTER_NUM
        self.IP_DOG = IP_DOG
        self.AUTH_VERSION = AUTH_VERSION
        self.SALT = SALT
        self.KEEP_ALIVE_VERSION = KEEP_ALIVE_VERSION
        self.ROR_VERSION = ROR_VERSION
        self.AUTH_INFO = None  # 在 login 阶段初始化


class Drcom:
    """
    Drcom 客户端运行所需要的一切

    :param conf: 处理后的配置项. 将从 conf 的属性读取配置, 例如 conf.username 等.
    :type conf: :class:`Namespace`
    """

    def __init__(self, conf):
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
        self.CONTROL_CHECK_STATUS = conf.CONTROL_CHECK_STATUS
        self.ADAPTER_NUM = conf.ADAPTER_NUM
        self.KEEP_ALIVE_VERSION = conf.KEEP_ALIVE_VERSION
        self.AUTH_VERSION = conf.AUTH_VERSION
        self.IPDOG = conf.IPDOG
        self.SALT = conf.SALT
        self.ror_version = conf.ror_version

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(10)
        for i in range(60000, 65535):
            try:
                self.bind_port = i
                self.socket.bind((self.bind_ip, self.bind_port))
                break
            except OSError:  # errno 98 address already in use
                continue

        self.socket.settimeout(3)
        # 将在 login 时被赋值, 在 logout 时使用
        self.AUTH_INFO = None
        self.KEEPALIVE_INTERVAL = 20

    def challenge(self, rand_num):
        counter = RuntimeCounter()
        while True:
            pack = struct.pack("<H", int(rand_num) % 0xffff)
            self.socket.sendto(
                b"\x01\x02" + pack + b"\x09" + b"\x00"*15,
                (self.server, self.port)
            )
            try:
                data, address = self.socket.recvfrom(1024)
                counter.clear()
            except socket.timeout:
                counter()
                continue
            if address == (self.server, self.port):
                break
            if data[:1] != b'\x02':     # 对字节不要 data[0]
                raise ChallengeException()
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
        """
        struct  _tagLoginPacket {
            struct _tagDrCOMHeader Header;
            unsigned char PasswordMd5[MD5_LEN];
            char Account[ACCOUNT_MAX_LEN];
            unsigned char ControlCheckStatus;
            unsigned char AdapterNum;
            unsigned char MacAddrXORPasswordMD5[MAC_LEN];
            unsigned char PasswordMd5_2[MD5_LEN];
            unsigned char HostIpNum;
            unsigned int HostIPList[HOST_MAX_IP_NUM];
            unsigned char HalfMD5[8];
            unsigned char DogFlag;
            unsigned int unkown2;
            struct _tagHostInfo HostInfo;
            unsigned char ClientVerInfoAndInternetMode;
            unsigned char DogVersion;
        };
        """
        # _tagLoginPacket.Header
        data += b'\x03\x01\x00' + bytes([len(self.username) + 20])
        # _tagLoginPacket.PasswordMD5
        data += md5sum(b'\x03\x01' + self.SALT + self.password.encode())
        # _tagLoginPacket.Account
        data += (self.username.encode() + b'\x00'*36)[:36]
        # _tagLoginPacket.ControlCheckStatus
        data += self.CONTROL_CHECK_STATUS
        # _tagLoginPacket.AdapterNum
        data += self.ADAPTER_NUM
        # _tagLoginPacket.MacAddrXORPasswordMD5
        data += dump(
            int(
                binascii.hexlify(data[4:10]),
                base=16
            ) ^ self.mac
        )[-6:]
        # _tagLoginPacket.PasswordMD5_2
        data += md5sum(b'\x01' + self.password.encode() +
                       self.SALT + b'\x00'*4)
        # _tagLoginPacket.HostIpNum
        data += b'\x01'
        # _tagLoginPacket.HostIPList
        data += b''.join(
            [bytes([int(i)]) for i in self.host_ip.split('.')]
        )
        data += b'\x00'*12
        # _tagLoginPacket.HalfMD5 [8]
        data += md5sum(data + b'\x14\x00\x07\x0B')[:8]
        # _tagLoginPacket.DogFlag
        data += self.IPDOG
        # _tagLoginPacket.unkown2
        data += b'\x00'*4
        # _tagLoginPacket.HostInfo
        """
        struct  _tagHostInfo {
            char HostName[HOST_NAME_MAX_LEN];
            unsigned int DNSIP1;
            unsigned int DHCPServerIP;
            unsigned int DNSIP2;
            unsigned int WINSIP1;
            unsigned int WINSIP2;
            struct _tagOSVersionInfo OSVersion;
        };
        """
        # _tagHostInfo.HostName
        data += (self.host_name.encode() + b'\x00'*32)[:32]
        # _tagHostInfo.DNSIP1
        data += b''.join(
            [bytes([int(i)]) for i in self.dns.split('.')]
        )
        # _tagHostInfo.DHCPServerIP
        data += b''.join(
            [bytes([int(i)]) for i in self.dhcp_server.split('.')]
        )
        # _tagHostInfo.DNSIP2
        data += b'\x00'*4
        # _tagHostInfo.WINSIP1
        data += b'\x00'*4
        # _tagHostInfo.WINSIP2
        data += b'\x00'*4
        # _tagHostInfo.OSVersion
        """
        struct  _tagOSVersionInfo {
            unsigned int OSVersionInfoSize;
            unsigned int MajorVersion;
            unsigned int MinorVersion;
            unsigned int BuildNumber;
            unsigned int PlatformID;
            char ServicePack[128];
        };
        """
        # _tagOSVersionInfo.OSVersionInfoSize
        data += b'\x94\x00\x00\x00'
        # _tagOSVersionInfo.MajorVersion
        data += b'\x05\x00\x00\x00'
        # _tagOSVersionInfo.MinorVersion
        data += b'\x01\x00\x00\x00'
        # _tagOSVersionInfo.BuildNumber
        data += b'\x28\x0A\x00\x00'
        # _tagOSVersionInfo.PlatformID
        data += b'\x02\x00\x00\x00'
        # _tagOSVersionInfo.ServicePack
        data += (self.host_os.encode() + 32*b'\x00')[:32]
        data += b'\x00'*96
        data += self.AUTH_VERSION
        if self.ror_version:
            """
            struct _tagLDAPAuth {
                unsigned char Code;
                unsigned char PasswordLen;
                unsigned char Password[MD5_LEN];
            }
            """
            # _tagLDAPAuth.Code
            data += b'\x00'
            # _tagLDAPAuth.PasswordLen
            data += bytes([len(self.password)])
            # _tagLDAPAuth.Password
            data += ror(md5sum(b'\x03\x01' + self.SALT +
                               self.password), self.password)
        """
        struct  _tagDrcomAuthExtData {
            unsigned char Code;
            unsigned char Len;
            unsigned long CRC;
            unsigned short Option;
            unsigned char AdapterAddress[MAC_LEN];
        };
        """
        # _tagDrcomAuthExtData.Code
        data += b'\x02'
        # _tagDrcomAuthExtData.Len
        data += b'\x0c'
        # _tagDrcomAuthExtData.CRC
        data += checksum(
            data + b'\x01\x26\x07\x11\x00\x00' + dump(self.mac)
        )
        # _tagDrcomAuthExtData.Option
        data += b'\x00\x00'
        # _tagDrcomAuthExtData.AdapterAddress
        data += dump(self.mac)
        # auto logout / default: False
        data += b'\x00'
        # broadcast mode / default: False
        data += b'\x00'
        # unknown, 随机填充的
        data += b'\xe9\x13'
        return data

    def keepAlive(self, auth_info):
        srv_num = 0
        tail = b'\x00\x00\x00\x00'
        self.__keepAlive1(auth_info)
        tail, srv_num = self.__keepAlive2(srv_num, tail)
        time.sleep(self.KEEPALIVE_INTERVAL)
        # 稳定状态
        while True:
            self.__keepAlive1(auth_info)
            srv_num, tail = self.__keepAlive2_stable(srv_num, tail)
            time.sleep(self.KEEPALIVE_INTERVAL)

    def __keepAlive1(self, tail):
        counter = RuntimeCounter()
        data = b''
        foo = struct.pack("!H", int(time.time()) % 0xffff)
        data += b'\xff' + md5sum(
                b'\x03\x01' + self.SALT + self.password.encode()
        ) + b'\x00\x00\x00'
        data += tail
        data += foo + b'\x00\x00\x00\x00'
        self.socket.sendto(data, (self.server, self.port))
        while True:
            try:
                data, address = self.socket.recvfrom(1024)
            except socket.timeout:
                counter('keepAlive1 超时')
                continue
            counter.clear()
            if data[:1] == b'\x07':
                break

    def __keepAlive2(self, srv_num, tail):
        srv_num = self.__keepAlive2_1(srv_num, tail)
        tail, srv_num = self.__keepAlive2_2(srv_num, tail)
        tail, srv_num = self.__keepAlive2_3(srv_num, tail)
        return tail, srv_num

    def __keepAlive2_1(self, srv_num, tail):
        package = self.makeKeepAlivePackage(
            num=srv_num,
            tail=tail,
            type_=1,
            first=True,
        )
        while True:
            self.socket.sendto(package, (self.server, self.port))
            data, address = self.socket.recvfrom(1024)
            if (
                data.startswith(b'\x07\x00\x28\x00') or
                data.startswith(b'\x07' + bytes([srv_num]) + b'\x28\x00')
            ):
                break
            elif data[:1] == b'\x07' and data[2:3] == b'\x10':
                break
        return srv_num + 1

    def __keepAlive2_2(self, srv_num, tail):
        counter = RuntimeCounter()
        package = self.makeKeepAlivePackage(
            num=srv_num,
            tail=tail,
            type_=1,
        )
        self.socket.sendto(package, (self.server, self.port))
        while True:
            data, address = self.socket.recvfrom(1024)
            if data[:1] == b'\x07':
                counter.clear()
                break
            else:
                counter()
        return data[16:20], srv_num + 1  # tail

    def __keepAlive2_3(self, srv_num, tail):
        package = self.makeKeepAlivePackage(
            num=srv_num,
            tail=tail,
            type_=3
        )
        counter = RuntimeCounter()
        self.socket.sendto(package, (self.server, self.port))
        while True:
            data, address = self.socket.recvfrom(1024)
            if data[:1] == b'\x07':
                counter.clear()
                break
            else:
                counter()
        return data[16:20], srv_num + 1  # tail

    def __keepAlive2_stable(self, srv_num, tail):
        tail = self.__keepAlive2_stable_1(srv_num, tail)
        tail, srv_num = self.__keepAlive2_stable_2(srv_num, tail)
        return srv_num, tail

    def __keepAlive2_stable_1(self, srv_num, tail):
        while True:
            package = self.makeKeepAlivePackage(
                num=srv_num,
                tail=tail,
                type_=1
            )
            counter = RuntimeCounter()
            self.socket.sendto(package, (self.server, self.port))
            try:
                data, address = self.socket.recvfrom(1024)
            except socket.timeout:
                counter()
                continue
            counter.clear()
            return data[16:20]  # tail

    def __keepAlive2_stable_2(self, srv_num, tail):
        package = self.makeKeepAlivePackage(
            num=srv_num+1,
            tail=tail,
            type_=3,
        )
        counter = RuntimeCounter()
        self.socket.sendto(package, (self.server, self.port))
        try:
            data, address = self.socket.recvfrom(1024)
        except socket.timeout:
            counter()
        counter.clear()
        tail = data[16:20]
        srv_num = (srv_num + 2) % 127
        return tail, srv_num

    def login(self):
        """
        mkpkt -> send -> recv -> check

        check: 首字节必须为 04
        """
        counter = RuntimeCounter()
        while True:
            self.SALT = self.challenge(time.time()+random.randint(0xf, 0xff))
            packet = self.mkpkt()
            self.__login_send(packet, self.server, self.port)
            try:
                data, address = self.__login_recv()
            except socket.timeout:
                counter("login timeout")
                continue
            auth_info = self.__login_check(
                self.server, self.port, data, address, counter)
            if not auth_info is None:
                self.AUTH_INFO = auth_info
                counter.clear()
                return auth_info
            else:
                continue

    def __login_send(self, packet, server, port):
        self.socket.sendto(packet, (server, port))

    def __login_recv(self):
        data, address = self.socket.recvfrom(1024)
        return data, address

    def __login_check(self, server, port, data, address, counter: RuntimeCounter):
        if address == (server, port):
            if data[:1] == b'\x04':
                counter.clear()
                return data[23:39]
            else:
                counter('多次登录失败')
                return None
        else:
            counter('[login] exception occured.')
            return None

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
                int(binascii.hexlify(data[4:10]), 16) ^ self.mac
            )[-6:]

            data += self.AUTH_INFO

            self.socket.sendto(data, (self.server, self.port))
            data, address = self.socket.recvfrom(1024)
            if data[:1] == b'\x04':
                exit(0)

    def emptySocketBuffer(self):
        while True:
            try:
                data, address = self.socket.recvfrom(1024)
            except socket.timeout:
                break

    def run(self):
        print(
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
        auth_info = self.login()
        self.emptySocketBuffer()
        self.keepAlive(auth_info)
