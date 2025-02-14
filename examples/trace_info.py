# -*- coding: utf-8 -*-
"""
FileName: trace_info.py
Author: ZGC-BUPT-aimafan
Create: 2025-2-11
Description:
展示如何使用`TraceInfo`类查询流量trace统计，包括trace本身的统计和基于trace的flow的统计
"""

from pypcaptools.TrafficInfo import TraceInfo

db_config = {
    "host": "",
    "port": 3306,
    "user": "root",
    "password": "password",
    "database": "traffic",
    "table": "table",
}

# 创建TraceInfo实例
traffic_info = TraceInfo(db_config)
traffic_info.use_table("table_name")

# 获取表头和注释信息
transformed_data = traffic_info.table_columns
print(f"表头信息: {transformed_data}")

# 统计满足条件的流的个数
traffic_num = traffic_info.count_flows(
    "packet_length > 10 and accessed_website == '163.com'"
)
print(f"满足条件的流数量: {traffic_num}")

# 获取某个table中存储的网站列表
website_list = traffic_info.get_value_list_unique("accessed_website")
print(f"网站列表: {website_list}")

# 获取满足条件的payload序列
payload_list = traffic_info.get_payload("packet_length > 10")
print(f"满足条件的payload序列: {payload_list}")

# 返回一个字典，字典的键是trace_id，值是一个列表，列表中嵌套着子列表，子列表是Packet类，Packet类中包含[time, payload, dirct]
trace_payloads = traffic_info.get_trace_flow("accessed_website == 'bilibili.com'")
print(f"对应trace的payload序列: {trace_payloads}")
