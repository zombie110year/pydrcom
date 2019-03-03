# 错误原因

1. Windows 系统调用 os 判断文件存在性时, 实际调用了 cmd.exe (与 环境变量 ComSpec 有关), 而不能识别 ~ 符号.
2. Windows 系统下字符编码错误, 直接使用 compile 编译文件时, 以 gbk 编码读取文本

# 修复过程

1. 使用 os 读取环境变量 在 Windows 系统下读取 %APPDATA%/drcom/drcom.conf
2. 将配置文件以 utf-8 编码读入字符串, 再进行编译