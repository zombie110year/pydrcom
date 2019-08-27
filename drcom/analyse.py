import re
from binascii import hexlify
from pathlib import Path

from .config import DrcomConfig


def analysePcapng(file: Path) -> DrcomConfig:
    obj = DrcomConfig()
    text = file.read_bytes()
    offset = re.search(
        b"\xf0\x00\xf0\x00[\x00-\xff]{4}[\x03\x07]\x01", text).start() + 8
    if re.match(b"\x00\x00[\x00-\xff]{2}", text[offset+334:offset+338]):
        obj["core"]["ROR_VERSION"] = True
    else:
        obj["core"]["ROR_VERSION"] = False

    obj["core"]["CONTROL_CHECK_STATUS"] = bytes([text[offset + 56]])
    obj["core"]["ADAPTER_NUM"] = bytes([text[offset + 57]])
    obj["core"]["IP_DOG"] = bytes([text[offset + 105]])
    obj["core"]["AUTH_VERSION"] = text[offset + 310:offset + 312]
    obj["core"]["KEEP_ALIVE_VERSION"] = [i for i in re.findall(
        # 匹配到的是 (..) 对应的内容
        b"\xf0\x00\xf0\x00....\x07.\x5c\x28\x00\x0b\x01(..)", text) if i != b"\x0f\x27"][0]
    obj["drcom"]["server"] = ".".join(
        [str(i) for i in text[offset-12:offset-8]])
    return obj
