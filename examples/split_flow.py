# -*- coding: utf-8 -*-
"""
FileName: split_flow.py
Author: ZGC-BUPT-aimafan
Create: 2025-2-11
Description:
展示如何使用`PcapHandler`类分隔pcap文件。
"""

from pypcaptools import PcapHandler

origin_pcap = "/path/dir/filename"
output_dir = "/path/dir/output_dir"

# 创建PcapHandler实例
ph = PcapHandler(origin_pcap)

# 分流之后以pcap格式输出，TCP流允许从中途开始
session_num, output_path = ph.split_flow(
    output_dir, tcp_from_first_packet=False, output_type="pcap"
)
print(f"分流后总会话数: {session_num}, 输出路径: {output_path}")

# 分流之后以json格式输出，TCP流必须从握手阶段开始
session_num, output_path = ph.split_flow(
    output_dir, tcp_from_first_packet=True, output_type="json"
)
print(f"分流后总会话数: {session_num}, 输出路径: {output_path}")
