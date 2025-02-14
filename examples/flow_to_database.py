# -*- coding: utf-8 -*-
"""
FileName: flow_to_database.py
Author: ZGC-BUPT-aimafan
Create: 2025-2-11
Description:
展示如何将流数据以flow为单位插入数据库。
"""

from pypcaptools import PcapToDatabaseHandler

db_config = {
    "host": "",
    "port": 3306,
    "user": "root",
    "password": "password",
    "database": "traffic",
}

# 参数依次为 mysql配置、处理的pcap路径、应用层协议类型、存储的table名称、访问网站/行为、采集机器、table注释
# 如果行为中包含多个网站，用'_'进行分隔
handler = PcapToDatabaseHandler(
    db_config, "test.pcap", "https", "https", "github.com", "vultr10", "测试用数据集"
)

# 将流数据写入数据库
handler.flow_to_database()
print("流数据已成功加入到数据库")
