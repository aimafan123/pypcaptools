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
import socket
import struct
import time
import warnings
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Tuple, Union

import dpkt
from dpkt.utils import inet_to_str

# 定义常量，用于SNI提取的限制
MAX_PKT_FOR_SNI_EXTRACT = 30  # 每个流在尝试提取SNI时，最多处理的数据包数量
MAX_BYTES_FOR_SNI_EXTRACT = 8192  # 每个流在尝试提取SNI时，最多累积的字节数


class PcapHandler:
    """
    PcapHandler类用于处理PCAP文件，使用dpkt解析其中的网络流量数据。
    它提供方法来提取整个trace的序列，以及按流（flow）划分的序列。
    """

    def __init__(self, input_pcap_file: str):
        self.input_pcap_file = input_pcap_file
        # self.packets现在是一个轻量级字典的列表，而不是Scapy对象列表
        self.packets: List[Dict[str, Any]] = self._load_packets_with_dpkt()
        self.local_ip: str = self._determine_local_ip()

    def _load_packets_with_dpkt(self) -> List[Dict[str, Any]]:
        """使用dpkt加载PCAP文件中的所有数据包，并存储为轻量级格式。"""
        if (
            not os.path.exists(self.input_pcap_file)
            or os.path.getsize(self.input_pcap_file) == 0
        ):
            warnings.warn(f"PCAP文件 '{self.input_pcap_file}' 不存在或为空，跳过加载。")
            return []

        lightweight_packets = []
        try:
            with open(self.input_pcap_file, "rb") as f:
                pcap_reader = dpkt.pcap.Reader(f)
                for timestamp, buf in pcap_reader:
                    try:
                        # 解析以太网层
                        eth = dpkt.ethernet.Ethernet(buf)

                        # 确保是IP包
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                        ip = eth.data

                        # 确保是TCP包
                        if not isinstance(ip.data, (dpkt.tcp.TCP)):
                            continue
                        transport = ip.data

                        # 将解析出的关键信息存入列表
                        lightweight_packets.append(
                            {
                                "ts": timestamp,
                                "ip": ip,
                                "transport": transport,
                            }
                        )
                    except (dpkt.dpkt.UnpackError, IndexError):
                        # 忽略无法解析的包
                        continue
            return lightweight_packets
        except Exception as e:
            warnings.warn(f"无法使用dpkt读取PCAP文件 '{self.input_pcap_file}': {e}")
            return []

    def _determine_local_ip(self) -> str:
        """
        将第一个捕获到的IP数据包的源IP地址认定为本地IP地址。
        """
        # 遍历所有数据包信息
        for pkt_data in self.packets:
            # 检查数据包是否包含IP层信息
            if pkt_data.get("ip"):
                # 如果包含，立即返回该数据包的源IP地址（需要格式转换）
                return socket.inet_ntoa(pkt_data["ip"].src)

        # 如果遍历完所有数据包都没有找到IP层，则返回空字符串
        return ""

    def get_trace_sequence(self) -> Dict[str, Any]:
        """
        获取整个PCAP文件（Trace）的整合数据序列。
        (接口和功能保持不变)
        """
        if not self.packets:
            return {
                # 保持原始接口的键名
                "timestamps_seq": [],
                "payload_seq": [],
                "direction_seq": [],
                "total_packet_count": 0,  # 键名对齐
                "capture_time": datetime.fromtimestamp(0),  # 键名对齐
            }

        timestamps_seq: List[float] = []
        payload_seq: List[int] = []
        direction_seq: List[int] = []

        start_time = float(self.packets[0]["ts"])

        for pkt_data in self.packets:
            timestamps_seq.append(float(pkt_data["ts"]) - start_time)

            # 直接从解析好的transport层获取payload长度
            payload_len = len(pkt_data["transport"].data)
            payload_seq.append(payload_len)

            direction = 0
            if self.local_ip:
                ip_layer = pkt_data["ip"]
                src_ip_str = socket.inet_ntoa(ip_layer.src)
                dst_ip_str = socket.inet_ntoa(ip_layer.dst)

                if src_ip_str == self.local_ip:
                    direction = 1  # 出站
                elif dst_ip_str == self.local_ip:
                    direction = -1  # 入站

            direction_seq.append(direction)

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
        (接口和功能保持不变)
        """
        flows = defaultdict(lambda: {"packets": [], "transport_protocol": None})
        for i, pkt_data in enumerate(self.packets):
            ip_layer = pkt_data["ip"]
            transport_layer = pkt_data["transport"]

            # 获取协议名称
            proto = transport_layer.__class__.__name__.upper()

            # IP地址和端口需要转换
            src_ip = socket.inet_ntoa(ip_layer.src)
            dst_ip = socket.inet_ntoa(ip_layer.dst)
            sport = transport_layer.sport
            dport = transport_layer.dport

            # flow_key 生成逻辑无变化
            if src_ip < dst_ip or (src_ip == dst_ip and sport < dport):
                flow_key = f"{proto}_{src_ip}:{sport}_{dst_ip}:{dport}"
            else:
                flow_key = f"{proto}_{dst_ip}:{dport}_{src_ip}:{sport}"

            flows[flow_key]["transport_protocol"] = proto

            flows[flow_key]["packets"].append((i + 1, pkt_data))

        processed_flows = {}
        trace_start_time = float(self.packets[0]["ts"]) if self.packets else 0

        for key, data in flows.items():
            # 解析端点信息和判断源/目的逻辑无变化
            parts = key.split("_")
            endpoint1, endpoint2 = parts[1], parts[2]
            ip1, port1_str = endpoint1.split(":")
            ip2, port2_str = endpoint2.split(":")
            port1, port2 = int(port1_str), int(port2_str)

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
                # 保持原始逻辑，以排序靠前的为源
                source_ip, source_port, destination_ip, destination_port = (
                    ip1,
                    port1,
                    ip2,
                    port2,
                )

            first_pkt_time = float(data["packets"][0][1]["ts"])

            timestamps_seq, payload_seq, direction_seq, trace_packet_indices = (
                [],
                [],
                [],
                [],
            )

            for index, p_data in data["packets"]:
                timestamps_seq.append(float(p_data["ts"]) - first_pkt_time)
                payload_seq.append(len(p_data["transport"].data))
                trace_packet_indices.append(index)

                # 判断方向
                pkt_src_ip = socket.inet_ntoa(p_data["ip"].src)
                direction_seq.append(1 if pkt_src_ip == source_ip else -1)

            flow_duration_ms = (
                float(data["packets"][-1][1]["ts"]) - first_pkt_time
            ) * 1000

            processed_flows[key] = {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": source_port,
                "destination_port": destination_port,
                "transport_protocol": data["transport_protocol"],
                "flow_start_time_ms": (first_pkt_time - trace_start_time) * 1000,
                "flow_duration_ms": flow_duration_ms,
                "timestamps_seq": timestamps_seq,
                "payload_seq": payload_seq,
                "direction_seq": direction_seq,
                "trace_packet_indices": trace_packet_indices,
            }
        return processed_flows


if __name__ == "__main__":
    test_pcap_file = "../test/direct_20250827011340_141.164.58.43_ko_apple.com.pcap"

    pcap_handler = PcapHandler(test_pcap_file)
    flow_sequences = pcap_handler.get_flow_sequences()
    print(flow_sequences)
