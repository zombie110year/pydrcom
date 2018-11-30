#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct
import time
from hashlib import md5
import sys
import os
import random
import binascii
from configs import *   # 读取配置

'''
AUTH_VERSION:
    unsigned char ClientVerInfoAndInternetMode;
    unsigned char DogVersion;
'''
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((bind_ip, port))
s.settimeout(3)

SALT = ''
# specified fields based on version
UNLIMITED_RETRY = True
EXCEPTION = False

if nic_name != '':
    bind_ip = bindNic()

class ChallengeException (Exception):
    def __init__(self):
        pass

class LoginException (Exception):
    def __init__(self):
        pass

def log(*args, **kwargs):
    s = ' '.join(args)
    print(s)

def bindNic():
    try:
        import fcntl
        def getIPAddr(ifname):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15])
            )[20:24])
        return getIPAddr(nic_name)
    except ImportError:
        print('Indicate nic feature need to be run under Unix based system.')
        return '0.0.0.0'
    except IOError:
        print(nic_name + 'is unacceptable !')
        return '0.0.0.0'
    finally:
        return '0.0.0.0'

def md5sum(s):
    m = md5()
    m.update(s)
    return m.digest()

def dump(n):
    s = '%x' % n
    if len(s) & 1:
        s = '0' + s
    return binascii.unhexlify(bytes(s, 'ascii'))

def ror(md5, pwd):
    ret = ''
    for i in range(len(pwd)):
        x = ord(md5[i]) ^ ord(pwd[i])
        ret += struct.pack("B", ((x<<3)&0xFF) + (x>>5))
    return ret

def challenge(svr,ran):
    while True:
        t = struct.pack("<H", int(ran)%(0xFFFF))
        s.sendto(b"\x01\x02" + t + b"\x09" + b"\x00"*15, (svr, port))
        try:
            data, address = s.recvfrom(1024)
            log('[challenge] recv', str(binascii.hexlify(data))[2:][:-1])
        except Exception:
            log('[challenge] timeout, retrying...')
            raise(Exception)

        if address == (svr, port):
            break
        else:
            continue
    log('[DEBUG] challenge:\n' + str(binascii.hexlify(data))[2:][:-1])
    if data[:1] != b'\x02':
        raise ChallengeException
    log('[challenge] challenge packet sent.')
    return data[4:8]

def buildKeepAlivePackage(number,random,tail,type=1,first=False):
    data = b'\x07'+ bytes([number]) + b'\x28\x00\x0B' + bytes([type])
    if first :
        data += b'\x0F\x27'
    else:
        data += KEEP_ALIVE_VERSION
    data += b'\x2F\x12' + b'\x00' * 6
    data += tail
    data += b'\x00' * 4
    #data += struct.pack("!H",0xdc02)
    if type == 3:
        foo = b''.join([bytes([int(i)]) for i in host_ip.split('.')]) # host_ip
        #CRC
        # edited on 2014/5/12, filled zeros to checksum
        # crc = packet_CRC(data+foo)
        crc = b'\x00' * 4
        #data += struct.pack("!I",crc) + foo + b'\x00' * 8
        data += crc + foo + b'\x00' * 8
    else: #packet type = 1
        data += b'\x00' * 16
    return data

# def packet_CRC(s):
#     ret = 0
#     for i in re.findall('..', s):
#         ret ^= struct.unpack('>h', i)[0]
#         ret &= 0xFFFF
#     ret = ret * 0x2c7
#     return ret

def checksum(s):
    ret = 1234
    for i in [x*4 for x in range(0, -(-len(s)//4))]:
        ret ^= int(binascii.hexlify(s[i:i+4].ljust(4, b'\x00')[::-1]), 16)
    ret = (1968 * ret) & 0xffffffff
    return struct.pack('<I', ret)

def mkpkt(salt, usr, pwd, mac):
    '''
	struct  _tagLoginPacket
	{
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
    '''
    data = b'\x03\x01\x00' + bytes([len(usr) + 20])
    data += md5sum(b'\x03\x01' + salt + pwd.encode())
    data += (usr.encode() + 36*b'\x00')[:36]
    data += CONTROLCHECKSTATUS
    data += ADAPTERNUM
    data += dump(int(binascii.hexlify(data[4:10]), 16)^mac)[-6:] #mac xor md51
    data += md5sum(b'\x01' + pwd.encode() + salt + b'\x00'*4) #md52
    data += b'\x01' # number of ip
    data += b''.join([bytes([int(i)]) for i in host_ip.split('.')]) #x.x.x.x ->
    data += b'\00' * 4 #your ipaddress 2
    data += b'\00' * 4 #your ipaddress 3
    data += b'\00' * 4 #your ipaddress 4
    data += md5sum(data + b'\x14\x00\x07\x0B')[:8] #md53
    data += IPDOG
    data += b'\x00'*4 # unknown2
    '''
	struct  _tagOSVERSIONINFO
	{
	    unsigned int OSVersionInfoSize;
	    unsigned int MajorVersion;
	    unsigned int MinorVersion;
	    unsigned int BuildNumber;
	    unsigned int PlatformID;
	    char ServicePack[128];
	};
	struct  _tagHostInfo
	{
	    char HostName[HOST_NAME_MAX_LEN];
	    unsigned int DNSIP1;
	    unsigned int DHCPServerIP;
	    unsigned int DNSIP2;
	    unsigned int WINSIP1;
	    unsigned int WINSIP2;
	    struct _tagDrCOM_OSVERSIONINFO OSVersion;
	};
    '''
    data += (host_name.encode() + 32 * b'\x00')[:32] # _tagHostInfo.HostName
    data += b''.join([bytes([int(i)]) for i in PRIMARY_DNS.split('.')]) # _tagHostInfo.DNSIP1
    data += b''.join([bytes([int(i)]) for i in dhcp_server.split('.')]) # _tagHostInfo.DHCPServerIP
    data += b'\x00\x00\x00\x00' # _tagHostInfo.DNSIP2
    data += b'\x00' * 4 # _tagHostInfo.WINSIP1
    data += b'\x00' * 4 # _tagHostInfo.WINSIP2
    data += b'\x94\x00\x00\x00' # _tagHostInfo.OSVersion.OSVersionInfoSize
    data += b'\x05\x00\x00\x00' # _tagHostInfo.OSVersion.MajorVersion
    data += b'\x01\x00\x00\x00' # _tagHostInfo.OSVersion.MinorVersion
    data += b'\x28\x0A\x00\x00' # _tagHostInfo.OSVersion.BuildNumber
    data += b'\x02\x00\x00\x00' # _tagHostInfo.OSVersion.PlatformID
    # _tagHostInfo.OSVersion.ServicePack
    data += (host_os.encode() + 32 * b'\x00')[:32]
    data += b'\x00' * 96
    # END OF _tagHostInfo

    data += AUTH_VERSION
    if ror_version:
        '''
	struct  _tagLDAPAuth
	{
	    unsigned char Code;
	    unsigned char PasswordLen;
	    unsigned char Password[MD5_LEN];
	};
        '''
        data += b'\x00' # _tagLDAPAuth.Code
        data += bytes([len(pwd)]) # _tagLDAPAuth.PasswordLen
        data += ror(md5sum(b'\x03\x01' + salt + pwd), pwd) # _tagLDAPAuth.Password
    '''
	struct  _tagDrcomAuthExtData
	{
	    unsigned char Code;
	    unsigned char Len;
	    unsigned long CRC;
	    unsigned short Option;
	    unsigned char AdapterAddress[MAC_LEN];
	};
    '''
    data += b'\x02' # _tagDrcomAuthExtData.Code
    data += b'\x0C' # _tagDrcomAuthExtData.Len
    data += checksum(data + b'\x01\x26\x07\x11\x00\x00' + dump(mac)) # _tagDrcomAuthExtData.CRC
    data += b'\x00\x00' # _tagDrcomAuthExtData.Option
    data += dump(mac) # _tagDrcomAuthExtData.AdapterAddress
    # END OF _tagDrcomAuthExtData

    data += b'\x00' # auto logout / default: False
    data += b'\x00' # broadcast mode / default : False
    data += b'\xE9\x13' #unknown, filled numbers randomly =w=

    log('[mkpkt]', str(binascii.hexlify(data))[2:][:-1])
    return data

def login(usr, pwd, svr):
    global SALT
    global AUTH_INFO

    i = 0
    while True:
        salt = challenge(svr, time.time()+random.randint(0xF, 0xFF))
        SALT = salt
        packet = mkpkt(salt, usr, pwd, mac)
        log('[login] send', str(binascii.hexlify(packet))[2:][:-1])
        s.sendto(packet, (svr, port))
        data, address = s.recvfrom(1024)
        log('[login] recv', str(binascii.hexlify(data))[2:][:-1])
        log('[login] packet sent.')
        if address == (svr, port):
            if data[:1] == b'\x04':
                log('[login] loged in')
                AUTH_INFO = data[23:39]
                break
            else:
                log('[login] login failed.')
                time.sleep(10)
                continue
        else:
            if i >= 5 and not UNLIMITED_RETRY:
                log('[login] exception occured.')
                sys.exit(1)
            else:
                continue

    log('[login] login sent')
    #0.8 changed:
    return data[23:39]
    #return data[-22:-6]

def logout(usr, pwd, svr, mac, auth_info):
    salt = challenge(svr, time.time()+random.randint(0xF, 0xFF))
    if salt:
        data = b'\x06\x01\x00' + bytes([len(usr) + 20])
        data += md5sum(b'\x03\x01' + salt + pwd.encode())
        data += (usr + 36*'\x00')[:36]
        data += CONTROLCHECKSTATUS
        data += ADAPTERNUM
        data += dump(int(binascii.hexlify(data[4:10]), 16)^mac)[-6:]
        # data += b'\x44\x72\x63\x6F' # Drco
        data += auth_info
        s.send(data)
        data, address = s.recvfrom(1024)
        if data[:1] == b'\x04':
            log('[logout_auth] logouted.')

def keepAlive1(salt, tail, pwd, svr):
    foo = struct.pack('!H',int(time.time())%0xFFFF)
    data = b'\xff' + md5sum(b'\x03\x01' + salt + pwd.encode()) + b'\x00\x00\x00'
    data += tail
    data += foo + b'\x00\x00\x00\x00'
    log('[keepAlive1] send', str(binascii.hexlify(data))[2:][:-1])

    s.sendto(data, (svr, port))
    while True:
        data, address = s.recvfrom(1024)
        if data[:1] == b'\x07':
            break
        else:
            log('[keepAlive1]recv/not expected', str(binascii.hexlify(data))[2:][:-1])
    log('[keepAlive1] recv', str(binascii.hexlify(data))[2:][:-1])

def keepAlive2(*args):
    #first keep_alive:
    #number = number (mod 7)
    #status = 1: first packet user sended
    #         2: first packet user recieved
    #         3: 2nd packet user sended
    #         4: 2nd packet user recieved
    #   Codes for test
    tail = ''
    packet = ''
    svr = server
    ran = random.randint(0, 0xFFFF)
    ran += random.randint(1, 10)   
    # 2014/10/15 add by latyas, maybe svr sends back a file packet
    svr_num = 0
    packet = buildKeepAlivePackage(svr_num,dump(ran), b'\x00'*4, 1, True)
    while True:
        log('[keepAlive2] send1', str(binascii.hexlify(packet))[2:][:-1])
        s.sendto(packet, (svr, port))
        data, address = s.recvfrom(1024)
        log('[keepAlive2] recv1', str(binascii.hexlify(data))[2:][:-1])
        if data.startswith(b'\x07\x00\x28\x00') or data.startswith(b'\x07' + bytes([svr_num]) + b'\x28\x00'):
            break
        elif data[:1] == b'\x07' and data[2:3] == b'\x10':
            log('[keepAlive2] recv file, resending..')
            svr_num = svr_num + 1
            # packet = keep_alive_package_builder(svr_num,dump(ran),'\x00'*4,1, False)
            break
        else:
            log('[keepAlive2] recv1/unexpected', str(binascii.hexlify(data))[2:][:-1])
    #log('[keepAlive2] recv1', str(binascii.hexlify(data))[2:][:-1])
    
    ran += random.randint(1, 10)   
    packet = buildKeepAlivePackage(svr_num, dump(ran), b'\x00'*4, 1, False)
    log('[keepAlive2] send2', str(binascii.hexlify(packet))[2:][:-1])
    s.sendto(packet, (svr, port))
    while True:
        data, address = s.recvfrom(1024)
        if data[:1] == b'\x07':
            svr_num = svr_num + 1
            break
        else:
            log('[keepAlive2] recv2/unexpected', str(binascii.hexlify(data))[2:][:-1])
    log('[keepAlive2] recv2', str(binascii.hexlify(data))[2:][:-1])
    tail = data[16:20]


    ran += random.randint(1, 10)   
    packet = buildKeepAlivePackage(svr_num, dump(ran), tail, 3, False)
    log('[keepAlive2] send3', str(binascii.hexlify(packet))[2:][:-1])
    s.sendto(packet, (svr, port))
    while True:
        data, address = s.recvfrom(1024)
        if data[:1] == b'\x07':
            svr_num = svr_num + 1
            break
        else:
            log('[keepAlive2] recv3/unexpected', str(binascii.hexlify(data))[2:][:-1])
    log('[keepAlive2] recv3', str(binascii.hexlify(data))[2:][:-1])
    tail = data[16:20]
    log("[keepAlive2] keepAlive2 loop was in daemon.")
    
    i = svr_num
    while True:
        try:
            time.sleep(20)
            keepAlive1(*args)
            ran += random.randint(1, 10)   
            packet = buildKeepAlivePackage(i, dump(ran), tail, 1, False)
            #log('DEBUG: keepAlive2,packet 4\n', str(binascii.hexlify(packet))[2:][:-1])
            log('[keepAlive2] send',str(i), str(binascii.hexlify(packet))[2:][:-1])
            s.sendto(packet, (svr, port))
            data, address = s.recvfrom(1024)
            log('[keepAlive2] recv', str(binascii.hexlify(data))[2:][:-1])
            tail = data[16:20]
            #log('DEBUG: keepAlive2,packet 4 return\n', str(binascii.hexlify(data))[2:][:-1])
        
            ran += random.randint(1, 10)   
            packet = buildKeepAlivePackage(i+1, dump(ran), tail, 3, False)
            #log('DEBUG: keepAlive2,packet 5\n', str(binascii.hexlify(packet))[2:][:-1])
            s.sendto(packet, (svr, port))
            log('[keepAlive2] send', str(i+1), str(binascii.hexlify(packet))[2:][:-1])
            data, address = s.recvfrom(1024)
            log('[keepAlive2] recv', str(binascii.hexlify(data))[2:][:-1])
            tail = data[16:20]
            #log('DEBUG: keepAlive2,packet 5 return\n', str(binascii.hexlify(data))[2:][:-1])
            i = (i+2) % 127 #must less than 128 ,else the keepAlive2() couldn't receive anything.
        except:
            pass

def emptySocketBuffer():
#empty buffer for some fucking schools
    log('starting to empty socket buffer')
    try:
        while True:
            data, address = s.recvfrom(1024)
            log('recived sth unexpected', str(binascii.hexlify(data))[2:][:-1])
            if s == '':
                break
    except:
        # get exception means it has done.
        log('exception in emptySocketBuffer')
        pass
    log('emptyed')

def main():
    log_temp = "auth svr: {auth_svr}\nusername: {username}\npassword: {password}\nmac: {mac}\nbind ip:{bind_ip}"
    log(log_temp.format(auth_svr=server,
    username=username, password=password,
    mac=str(hex(mac))[:-1], bind_ip=bind_ip))
    while True:
      try:
        package_tail = login(username, password, server)
      except LoginException:
        continue
      log('package_tail', str(binascii.hexlify(package_tail))[2:][:-1])
      #keepAlive1 is fucking bullshit!
      emptySocketBuffer()
      keepAlive1(SALT, package_tail, password, server)
      keepAlive2(SALT, package_tail, password, server)

if __name__ == "__main__":
    main()
