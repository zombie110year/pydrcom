学习源代码
===

# latest-wired-python3.py


## 函数

```py
md5()
bind_nic()
    get_ip_address()
log()
md5sum()
dump()
ror()
challenge()
keep_alive_package_builder()
keep_alive2()
checksum()
mkpkt()
login()
logout()
keep_alive1()
empty_socket_buffer()
daemon()
def main():
    if not IS_TEST:
        daemon()                # 在 Linux 系统中注册 PID
        exec(CONF, globals())   # 加载配置文件
    log("auth svr: " + server + "\nusername: " + username + "\npassword: " + password + "\nmac: " + str(hex(mac))[:-1])
    log("bind ip: " + bind_ip)
    while True:
      try:
        package_tail = login(username, password, server)
      except LoginException:
        continue
      log('package_tail', str(binascii.hexlify(package_tail))[2:][:-1])
      #keep_alive1 is fucking bullshit!
      empty_socket_buffer()
      keep_alive1(SALT, package_tail, password, server)
      keep_alive2(SALT, package_tail, password, server)
```

### 调用关系

### daemon

```python
def daemon():
    with open('/var/run/jludrcom.pid','w') as f:
        f.write(str(os.getpid()))
```

在 Linux 系统中注册 PID.

### login

```python
def login(usr, pwd, svr):
    global SALT
    global AUTH_INFO

    i = 0
    while True:
        salt = challenge(svr, time.time()+random.randint(0xF, 0xFF))
        SALT = salt
        packet = mkpkt(salt, usr, pwd, mac)
        log('[login] send', str(binascii.hexlify(packet))[2:][:-1])
        s.sendto(packet, (svr, 61440))
        data, address = s.recvfrom(1024)
        log('[login] recv', str(binascii.hexlify(data))[2:][:-1])
        log('[login] packet sent.')
        if address == (svr, 61440):
            if data[:1] == b'\x04':
                log('[login] loged in')
                AUTH_INFO = data[23:39]
                break
            else:
                log('[login] login failed.')
                if IS_TEST:
                    time.sleep(3)
                else:
                    time.sleep(30)
                continue
        else:
            if i >= 5 and UNLIMITED_RETRY == False :
                log('[login] exception occured.')
                sys.exit(1)
            else:
                continue

    log('[login] login sent')
    #0.8 changed:
    return data[23:39]
    #return data[-22:-6]
```
### bind_nic

NIC = Network Interface Controller, 网络适配器, 俗称网卡

## 全局变量

```python
nic_name = '' #Indicate your nic, e.g. 'eth0.2'.nic_name
bind_ip = '0.0.0.0'

SALT = ''
IS_TEST = True

CONF = "/etc/drcom.conf"
UNLIMITED_RETRY = True
EXCEPTION = False
DEBUG = False #log saves to file
LOG_PATH = '/tmp/drcom_client.log'
if IS_TEST:
    DEBUG = True
    LOG_PATH = 'drcom_client.log'


server = "192.168.100.150"
username = ""
password = ""
host_name = "LIYUANYUAN"
host_os = "8089D"
host_ip = "10.30.22.17"
PRIMARY_DNS = "114.114.114.114"
dhcp_server = "0.0.0.0"
mac = 0xb888e3051680
CONTROLCHECKSTATUS = b'\x20'
ADAPTERNUM = b'\x01'
KEEP_ALIVE_VERSION = b'\xdc\x02'
AUTH_VERSION = b'\x0a\x00'
IPDOG = b'\x01'
ror_version = False
```

## 函数之外的控制结构

```python
#70->73行:
if nic_name != '':
    bind_ip = bind_nic()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((bind_ip, 61440))
s.settimeout(3)
```

## 类

```py
class ChallengeException (Exception):
class LoginException (Exception):
```

定义错误处理.
