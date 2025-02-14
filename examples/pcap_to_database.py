# -*- coding: utf-8 -*-
"""
FileName: pcap_to_database.py
Author: ZGC-BUPT-aimafan
Create: 2025-2-11
Description:
展示如何将整个pcap以trace为单位插入mysql数据库。
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

# 将PCAP数据写入数据库
# 注意，会生成两个table，分别是table_trace和table_flow，前者存储trace的总体信息和序列字段，后者存储该trace中每个flow的信息和序列字段，两个库通过trace_id关联
handler.pcap_to_database()

print("PCAP数据已成功加入到数据库")
