from .config import DrcomConfig
from .context import DrcomContext


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
