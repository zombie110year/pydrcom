class DrcomContext:
    """Drcom 运行时上下文

    只做纯粹的发包, 解包工作.

    初始化上下文
    ============

    :param str server:      Drcom 认证服务器的地址
    :param int port:        服务端端口
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
    :param bool ROR_VERSION:
    """

    def __init__(self,
                 server: str,
                 port: int,
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
                 ROR_VERSION: bool,):
        """初始化上下文

        :param str server:      Drcom 认证服务器的地址
        :param int port:        服务端端口
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
        self.port = port
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
