########
问题排查
########

建立连接时经常超时
==================

日志中出现类似于::

    2019-03-17 21:48:16,845 - WARNING: [challenge] timeout, retrying...
    2019-03-17 21:48:19,857 - WARNING: [challenge] timeout, retrying...
    2019-03-17 21:48:22,863 - WARNING: [challenge] timeout, retrying...
    2019-03-17 21:48:25,868 - WARNING: [challenge] timeout, retrying...

或者::

    2019-03-17 21:43:38,833 - INFO: [keepAlive1] send
    2019-03-17 21:43:38,838 - DEBUG: ff7c50007ded229e3e602eb8fae2d4efb20000004472636f0afe0704e68b0afdc2cc0137ab9800000000
    keepAlive1 超时
    程序异常退出

等等, 代表着无法从服务器接收到数据.

由于是 UDP 连接, 所以有可能是存在另一名用户使用了相同的 IP.
此现象可能出现在本机固定 IP 并且有一段时间未使用的情况下.

解决方法:

1.  更换本机 IP
2.  取消静态 IP, 使用 DHCP 自动分配.
