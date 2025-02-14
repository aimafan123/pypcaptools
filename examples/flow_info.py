# -*- coding: utf-8 -*-
"""
FileName: flow_info.py
Author: ZGC-BUPT-aimafan
Create: 2025-2-11
Description:
展示如何使用`FlowInfo`类查询flow统计。
"""

from pypcaptools.TrafficInfo import FlowInfo

db_config = {
    "host": "",
    "port": 3306,
    "user": "root",
    "password": "password",
    "database": "traffic",
}

# 创建FlowInfo实例
traffic_info = FlowInfo(db_config)
traffic_info.use_table("table_name")

# 获取表头信息
transformed_data = traffic_info.table_columns
print(f"表头信息: {transformed_data}")

# 统计满足条件的流的个数
traffic_num = traffic_info.count_flows(
    "packet_length > 10 and accessed_website == '163.com'"
)
print(f"满足条件的流数量: {traffic_num}")

# 获取独特的网站列表
website_list = traffic_info.get_value_list_unique("accessed_website")
print(f"网站列表: {website_list}")

# 获取满足条件的payload序列
payload_list = traffic_info.get_payload("packet_length > 10")
print(f"满足条件的payload序列: {payload_list}")
