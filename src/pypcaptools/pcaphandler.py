# -*- coding: utf-8 -*-
"""
FileName: pcaphandler.py
Author: ZGC-BUPT-aimafan
Create:
Description:
处理PCAP文件，解析其中的网络流量数据，并将这些数据按照特定的方式进行分流。
本模块定义了 PcapHandler 类，提供了多个方法来解析、处理和保存流量数据，
包括提取IP数据包、计算负载大小、按TCP/UDP流分割流量，以及将处理后的结果保存为PCAP或JSON格式。
用户可以指定输出的格式（PCAP或JSON），并根据设定的条件（如最小数据包数）进行分流操作。
"""

import json
import os
import struct
import warnings
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Tuple, Union

import dpkt
import scapy.all as scapy
from dpkt.utils import inet_to_str
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Packet

# 定义常量，用于SNI提取的限制
MAX_PKT_FOR_SNI_EXTRACT = 30  # 每个流在尝试提取SNI时，最多处理的数据包数量
MAX_BYTES_FOR_SNI_EXTRACT = 8192  # 每个流在尝试提取SNI时，最多累积的字节数


class PcapHandler:
    """
    PcapHandler类用于处理PCAP文件，使用Scapy解析其中的网络流量数据。
    它提供方法来提取整个trace的序列，以及按流（flow）划分的序列。
    """

    def __init__(self, input_pcap_file: str):
        self.input_pcap_file = input_pcap_file
        self.packets: scapy.PacketList = self._load_scapy_packets()
        self.local_ip: str = self._determine_local_ip()

    def _load_scapy_packets(self) -> scapy.PacketList:
        """使用Scapy加载PCAP文件中的所有数据包。"""
        if (
            not os.path.exists(self.input_pcap_file)
            or os.path.getsize(self.input_pcap_file) == 0
        ):
            warnings.warn(f"PCAP文件 '{self.input_pcap_file}' 不存在或为空，跳过加载。")
            return scapy.PacketList()
        try:
            return scapy.rdpcap(self.input_pcap_file)
        except Exception as e:
            warnings.warn(f"无法使用Scapy读取PCAP文件 '{self.input_pcap_file}': {e}")
            return scapy.PacketList()

    def _determine_local_ip(self) -> str:
        """
        将第一个捕获到的IP数据包的源IP地址认定为本地IP地址。
        """
        # 遍历所有数据包
        for pkt in self.packets:
            # 检查数据包是否包含IP层
            if pkt.haslayer(IP):
                # 如果包含，立即返回该数据包的源IP地址
                return pkt[IP].src

        # 如果遍历完所有数据包都没有找到IP层，则返回空字符串
        return ""

    def get_trace_sequence(self) -> Dict[str, Any]:
        """
        获取整个PCAP文件（Trace）的整合数据序列。
        """
        if not self.packets:
            return {
                "timestamps_seq": [],
                "payload_seq": [],
                "direction_seq": [],
                "packet_count": 0,
                "start_time": 0,
            }

        timestamps_seq: List[float] = []
        payload_seq: List[int] = []
        direction_seq: List[int] = []
        # ### MODIFIED ###: 使用 self.packets[0].time 确保即使只有一个包也能正确获取时间
        start_time = float(self.packets[0].time) if self.packets else 0

        for pkt in self.packets:
            # ### MODIFIED ###: 统一时间戳为相对于开始时间的浮点数秒
            timestamps_seq.append(float(pkt.time) - start_time)

            payload_len = 0
            if pkt.haslayer(TCP):
                payload_len = len(pkt[TCP].payload)
            elif pkt.haslayer(UDP):
                payload_len = len(pkt[UDP].payload)
            elif pkt.haslayer(IP):  # Fallback for non-TCP/UDP IP packets
                payload_len = len(pkt[IP].payload)

            payload_seq.append(payload_len)

            direction = 0
            if self.local_ip and pkt.haslayer(IP):
                # ### MODIFIED ###: 数据库模型中方向为 1 (出) / -1 (入)
                if pkt[IP].src == self.local_ip:
                    direction = 1  # 出站
                elif pkt[IP].dst == self.local_ip:
                    direction = -1  # 入站

            direction_seq.append(direction)

        # ### MODIFIED ###: 字典的键名与数据库列名对齐
        return {
            "timestamps_seq": timestamps_seq,
            "payload_seq": payload_seq,
            "direction_seq": direction_seq,
            "total_packet_count": len(self.packets),
            "capture_time": datetime.fromtimestamp(start_time),
        }

    def get_flow_sequences(self) -> Dict[str, Dict[str, Any]]:
        """
        将PCAP数据包按五元组划分为不同的流（Flow）。
        """
        flows = defaultdict(
            lambda: {"packets": [], "transport_protocol": None, "sni": None}
        )

        for pkt in self.packets:
            if not pkt.haslayer(IP) or not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                continue

            ip_layer, transport_layer = pkt[IP], pkt.getlayer(TCP) or pkt.getlayer(UDP)
            proto = transport_layer.name.upper()

            # ... (flow_key 生成逻辑无变化) ...
            if ip_layer.src < ip_layer.dst or (
                ip_layer.src == ip_layer.dst
                and transport_layer.sport < transport_layer.dport
            ):
                flow_key = f"{proto}_{ip_layer.src}:{transport_layer.sport}_{ip_layer.dst}:{transport_layer.dport}"
            else:
                flow_key = f"{proto}_{ip_layer.dst}:{transport_layer.dport}_{ip_layer.src}:{transport_layer.sport}"

            flows[flow_key]["transport_protocol"] = proto
            flows[flow_key]["packets"].append(pkt)

        processed_flows = {}
        for key, data in flows.items():
            # ... (解析端点信息和判断源/目的逻辑无变化) ...
            parts = key.split("_")
            endpoint1, endpoint2 = parts[1], parts[2]
            ip1, port1 = endpoint1.split(":")
            ip2, port2 = endpoint2.split(":")
            port1, port2 = int(port1), int(port2)

            if self.local_ip and self.local_ip == ip1:
                source_ip, source_port, destination_ip, destination_port = (
                    ip1,
                    port1,
                    ip2,
                    port2,
                )
            elif self.local_ip and self.local_ip == ip2:
                source_ip, source_port, destination_ip, destination_port = (
                    ip2,
                    port2,
                    ip1,
                    port1,
                )
            else:
                source_ip, source_port, destination_ip, destination_port = (
                    ip1,
                    port1,
                    ip2,
                    port2,
                )

            first_pkt_time = float(data["packets"][0].time)

            timestamps_seq, payload_seq, direction_seq = [], [], []

            for p in data["packets"]:
                timestamps_seq.append(float(p.time) - first_pkt_time)

                transport_layer = p.getlayer(data["transport_protocol"])
                payload_seq.append(
                    len(transport_layer.payload)
                    if transport_layer and hasattr(transport_layer, "payload")
                    else 0
                )

                direction_seq.append(1 if p[IP].src == source_ip else -1)

            # ### MODIFIED ###: 字典键名与数据库列名对齐，并增加流持续时间
            processed_flows[key] = {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": source_port,
                "destination_port": destination_port,
                "transport_protocol": data["transport_protocol"],
                "flow_start_time_ms": (
                    first_pkt_time
                    - (float(self.packets[0].time) if self.packets else 0)
                )
                * 1000,
                "flow_duration_ms": (float(data["packets"][-1].time) - first_pkt_time)
                * 1000,
                "timestamps_seq": timestamps_seq,
                "payload_seq": payload_seq,
                "direction_seq": direction_seq,
            }
        return processed_flows


if __name__ == "__main__":
    test_pcap_file = "../test/direct_20250827011340_141.164.58.43_ko_apple.com.pcap"

    pcap_handler = PcapHandler(test_pcap_file)
    trace_sequences = pcap_handler.get_trace_sequence()
    print(trace_sequences)
