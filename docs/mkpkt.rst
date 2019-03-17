####################
mkpkt 构建的数据结构
####################

一个 packet 和三个结构体有关

.. code-block:: c

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

.. code-block:: c

    struct  _tagHostInfo {
        char HostName[HOST_NAME_MAX_LEN];
        unsigned int DNSIP1;
        unsigned int DHCPServerIP;
        unsigned int DNSIP2;
        unsigned int WINSIP1;
        unsigned int WINSIP2;
        struct _tagOSVersionInfo OSVersion;
    };

.. code-block:: c

    struct  _tagOSVersionInfo {
        unsigned int OSVersionInfoSize;
        unsigned int MajorVersion;
        unsigned int MinorVersion;
        unsigned int BuildNumber;
        unsigned int PlatformID;
        char ServicePack[128];
    };

.. code-block:: c

    struct  _tagDrcomAuthExtData {
        unsigned char Code;
        unsigned char Len;
        unsigned long CRC;
        unsigned short Option;
        unsigned char AdapterAddress[MAC_LEN];
    };
