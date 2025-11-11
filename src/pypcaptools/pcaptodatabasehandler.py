# -*- coding: utf-8 -*-
"""
FileName: pcaptodatabasehandler.py
Author: ZGC-BUPT-aimafan
Create:
Description:
PcapToDatabaseHandler 类是 PcapHandler 类的扩展，旨在将处理后的网络流量数据存储到数据库中。
该类的构造函数接受数据库配置信息、输入的 PCAP 文件路径、协议类型、访问的网站、采集机器信息以及注释等参数。
在 flow_to_database 方法中，该类会解析 PCAP 文件，将其中的 TCP 流数据分割，
并将数据以 flow 为单位存入数据库中的特定表，不会保留完整的 trace 信息。
pcap_to_database 方法则会同时生成 trace 和 flow 两个表，用于保留更详细的 trace 信息。
"""

import json
import os
import re
import warnings
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple, Union

import mysql.connector

# 从父类和自定义模块导入必要的组件
from pypcaptools.pcaphandler import PcapHandler
from pypcaptools.TrafficDB.FlowDB import FlowDB
from pypcaptools.TrafficDB.ResourceDB import ResourceDB
from pypcaptools.TrafficDB.TraceDB import TraceDB
from pypcaptools.util import DBConfig, serialization

# 定义 trace 表中每个流的最大数据包数量，用于限制序列化数据的大小
TRACE_MAX_PKT_NUM = 600000


def initialize_database_schema(db_config: DBConfig, base_table_name: str):
    """
    执行一次性的数据库和表结构初始化。
    这个函数是独立的，不属于任何类。每次运行最开始可以调用这个函数来确保数据库和表的存在。
    """
    print(f"开始检查并初始化数据库和表结构 (基础名称: {base_table_name})...")
    try:
        # 完整的表名
        trace_table = f"{base_table_name}_trace"
        flow_table = f"{base_table_name}_flow"
        resource_table = f"{base_table_name}_resource"

        # 实例化DB Handler
        trace_db = TraceDB(table=trace_table, **db_config)
        flow_db = FlowDB(table=flow_table, trace_table_name=trace_table, **db_config)
        resource_db = ResourceDB(
            table=resource_table, flow_table_name=flow_table, **db_config
        )

        # 依次执行初始化
        with trace_db as db:
            db.setup_database()
            db.create_table()
        with flow_db as db:
            db.create_table()
        with resource_db as db:
            db.create_table()

        print("数据库和表结构初始化完成。")
        return True
    except Exception as e:
        # print 的 exc_info 参数无效，直接打印异常并保留可读性
        print(f"数据库初始化失败: {e}")
        return False


class PcapToDatabaseHandler(PcapHandler):
    """
    继承自 PcapHandler，实现将PCAP和关联的JSON文件数据存入由基础名称动态定义的三张表中。
    """

    def __init__(
        self,
        db_config: DBConfig,
        base_table_name: str,
        input_pcap_file: str,
        input_json_file: str,
        protocol: str,
        accessed_website: str,
        collection_machine: str = "",
    ):
        super().__init__(input_pcap_file)

        trace_table = f"{base_table_name}_trace"
        flow_table = f"{base_table_name}_flow"
        resource_table = f"{base_table_name}_resource"

        self.trace_db = TraceDB(table=trace_table, **db_config)
        self.flow_db = FlowDB(
            table=flow_table, trace_table_name=trace_table, **db_config
        )
        self.resource_db = ResourceDB(
            table=resource_table, flow_table_name=flow_table, **db_config
        )

        self.input_json_file = input_json_file
        self.protocol = protocol
        self.accessed_website = accessed_website
        self.collection_machine = collection_machine

    def pcap_to_database(self) -> bool:
        """
        将PCAP和JSON数据导入数据库。
        使用三个DB Handler类来执行操作。
        """
        if not self.packets:
            print(f"PCAP文件 '{self.input_pcap_file}' 为空或加载失败，无法入库。")
            return False

        try:
            with open(self.input_json_file, "r") as f:
                json_data = json.load(f)
        except Exception as e:
            print(f"无法读取或解析JSON文件 '{self.input_json_file}': {e}")
            return False

        # 从PcapHandler获取解析好的数据
        trace_pcap_data = self.get_trace_sequence()
        flows_pcap_data = self.get_flow_sequences()

        tcp_flow_count = sum(
            1
            for flow in flows_pcap_data.values()
            if flow.get("transport_protocol") == "TCP"
        )

        try:
            # --- 步骤 1: 插入 `traces` 表 ---
            # 准备 `traces` 表所需的数据字典
            trace_db_data = {
                "accessed_website": self.accessed_website,
                "capture_time": trace_pcap_data["capture_time"],
                "timestamps_seq": trace_pcap_data["timestamps_seq"],
                "payload_seq": trace_pcap_data["payload_seq"],
                "direction_seq": trace_pcap_data["direction_seq"],
                "protocol": self.protocol,
                "collection_machine": self.collection_machine,
                "pcap_path": self.input_pcap_file,
                "json_path": self.input_json_file,
                "flow_count": tcp_flow_count,
                "total_packet_count": trace_pcap_data["total_packet_count"],
            }

            trace_id = 0
            # 使用TraceDB的上下文管理器
            with self.trace_db as db:
                trace_id = db.add_trace(trace_db_data)

            if trace_id <= 0:
                print(f"插入Trace失败或已存在，跳过。网站: {self.accessed_website}")
                return False

            print(f"成功插入trace记录到 '{self.trace_db.table}', ID: {trace_id}")

            # --- 步骤 2 & 3: 循环插入 `flows` 和 `resources` 表 ---
            flows_to_insert = []
            resources_to_insert = []
            flow_id_map = {}  # 用于存储 pcap_flow_key -> 数据库flow_id 的映射

            for json_flow_key, json_flow_info in json_data.items():
                # 解析JSON key以匹配PCAP key
                match = re.search(
                    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+) <-> (\d{1,3}(?:\.\d{1,3}){3}):(\d+)",
                    json_flow_key,
                )
                if not match:
                    warnings.warn(f"无法解析JSON key '{json_flow_key}'，跳过此流。")
                    continue

                ip1, port1, ip2, port2 = match.groups()
                port1, port2 = int(port1), int(port2)

                # 查找所有可能的pcap_flow_key (TCP和UDP)
                pcap_flow_key_options = []
                for proto in ["TCP", "UDP"]:
                    if ip1 < ip2 or (ip1 == ip2 and port1 < port2):
                        pcap_flow_key_options.append(
                            f"{proto}_{ip1}:{port1}_{ip2}:{port2}"
                        )
                    else:
                        pcap_flow_key_options.append(
                            f"{proto}_{ip2}:{port2}_{ip1}:{port1}"
                        )

                pcap_flow = None
                matched_pcap_key = None
                for key_option in pcap_flow_key_options:
                    if key_option in flows_pcap_data:
                        pcap_flow = flows_pcap_data[key_option]
                        matched_pcap_key = key_option
                        break

                if not pcap_flow:
                    warnings.warn(
                        f"在PCAP中未找到与JSON key '{json_flow_key}' 匹配的流。"
                    )
                    continue

                # 准备 `flows` 表的数据
                flow_db_data = pcap_flow.copy()  # 复制pcap解析的数据
                flow_db_data["trace_id"] = trace_id  # 关联到主表
                # 如果PCAP中没提取到SNI，则使用JSON中的
                if not flow_db_data.get("sni"):
                    flow_db_data["sni"] = json_flow_info.get("sni")

                flows_to_insert.append(flow_db_data)

                # 暂存resource数据 + 时间计算所需的flow上下文
                flow_id_map[matched_pcap_key] = {
                    "resources": json_flow_info.get("resources", []),
                    "flow_start_time_ms": flow_db_data.get("flow_start_time_ms", 0),
                    "timestamps_seq": flow_db_data.get("timestamps_seq", []),
                }

            # --- 步骤 2.1: 批量插入 `flows` ---
            with self.flow_db as db:
                db.add_flows(flows_to_insert)
                just_inserted_flows = db.query(
                    f"SELECT id, source_ip, source_port, destination_ip, destination_port, transport_protocol FROM `{db.table}` WHERE trace_id = %s",
                    (trace_id,),
                )
                # 创建一个用于快速查找的键
                for inserted_flow in just_inserted_flows:
                    proto = inserted_flow["transport_protocol"]
                    ip1, p1 = inserted_flow["source_ip"], inserted_flow["source_port"]
                    ip2, p2 = (
                        inserted_flow["destination_ip"],
                        inserted_flow["destination_port"],
                    )
                    if ip1 < ip2 or (ip1 == ip2 and p1 < p2):
                        pcap_key = f"{proto}_{ip1}:{p1}_{ip2}:{p2}"
                    else:
                        pcap_key = f"{proto}_{ip2}:{p2}_{ip1}:{p1}"

                    if pcap_key in flow_id_map:
                        flow_id_map[pcap_key]["id"] = inserted_flow["id"]

            # --- 步骤 3.1: 准备并批量插入 `resources` ---
            for pcap_key, flow_info in flow_id_map.items():
                if "id" not in flow_info:
                    continue  # 如果流未成功插入，则跳过其资源
                flow_id = flow_info["id"]
                flow_start_ms = flow_info.get("flow_start_time_ms", 0)
                flow_ts_seq = flow_info.get("timestamps_seq", [])

                for resource in flow_info.get("resources", []):
                    # 过滤不完整的资源
                    if "incomplete" in resource.get("url", "") or not resource.get(
                        "status"
                    ):
                        continue

                    packet_seq_list = resource.get("response_packet_nums", [])
                    response_start_ts = None
                    response_end_ts = None

                    if (
                        isinstance(packet_seq_list, list)
                        and packet_seq_list
                        and flow_ts_seq
                    ):
                        is_zero_based = 0 in packet_seq_list or (
                            min(packet_seq_list) == 0
                        )
                        idxs = []
                        for n in packet_seq_list:
                            i = n if is_zero_based else n - 1
                            if 0 <= i < len(flow_ts_seq):
                                idxs.append(i)

                        if idxs:
                            start_offset_s = min(flow_ts_seq[i] for i in idxs)
                            end_offset_s = max(flow_ts_seq[i] for i in idxs)
                            flow_start_dt = trace_pcap_data["capture_time"] + timedelta(
                                milliseconds=flow_start_ms
                            )
                            response_start_ts = flow_start_dt + timedelta(
                                seconds=start_offset_s
                            )
                            response_end_ts = flow_start_dt + timedelta(
                                seconds=end_offset_s
                            )

                    # 如果JSON中提供了绝对时间戳，优先使用它们
                    try:
                        if resource.get("response_start_time") is not None:
                            response_start_ts = datetime.fromtimestamp(
                                float(resource.get("response_start_time"))
                            )
                        if resource.get("response_end_time") is not None:
                            response_end_ts = datetime.fromtimestamp(
                                float(resource.get("response_end_time"))
                            )
                    except Exception:
                        # 如果转换失败，保留之前计算的结果或None
                        pass

                    resources_to_insert.append(
                        {
                            "flow_id": flow_id,
                            "stream_id": resource.get("stream_id"),
                            "url": resource.get("url"),
                            "http_status": int(resource.get("status"))
                            if resource.get("status") is not None
                            else None,
                            "content_type": resource.get("content_type"),
                            "resource_size_bytes": resource.get("resource_data_size"),
                            "server_packet_count": len(packet_seq_list),
                            "trace_packet_indices": packet_seq_list,
                            "response_start_ts": response_start_ts,
                            "response_end_ts": response_end_ts,
                            "latency_ms": float(resource.get("ttfb_sec", 0)) * 1000,
                        }
                    )

            if resources_to_insert:
                with self.resource_db as db:
                    inserted_count = db.add_resources(resources_to_insert)
                    print(
                        f"成功批量插入 {inserted_count} 条resource记录到 '{db.table}'。"
                    )

            print(f"成功处理并提交Trace ID: {trace_id} 的所有数据。")
            return True

        except mysql.connector.Error as err:
            print(f"数据库操作失败: {err}")
            # 注意：由于使用了多个事务（每个'with'块一个），回滚不是原子性的。
            # 这是一个简化的实现，对于严格的原子性要求，需要共享连接和事务。
            return False
        except Exception as e:
            print(f"处理PCAP/JSON文件时发生未知错误: {e}")
            return False


if __name__ == "__main__":
    # --- 示例数据库配置 ---
    # 请根据您的实际数据库环境修改以下配置信息
    db_config: DBConfig = {
        "host": "192.168.194.63",  # 数据库主机名或IP地址
        "port": 3306,  # 数据库端口
        "user": "root",  # 数据库用户名
        "password": "aimafan",  # 数据库密码
        "database": "WebsitesTraffic_test",  # 数据库名称
    }
    my_base_table_name = "trojan_top_100"

    # --- 示例 PCAP 文件路径 ---
    # 请确保此路径指向一个实际存在的 PCAP 文件，或在运行前创建此文件
    # 例如，您可以下载一个测试用的 PCAP 文件到当前目录
    test_pcap_file = "/home/aimafan/Documents/mycode/pypcaptools/test/81045_20251020_16_20_02_github.com.pcap"
    test_json_file = "/home/aimafan/Documents/mycode/pypcaptools/test/results.json"

    # --- 测试数据参数 ---
    protocol_type = "trojan"  # 示例协议类型
    trace_table_name = flow_table_name = "trojan"  # 存储 Flow 数据的表名

    accessed_website_name = "apple.com"  # 访问的网站
    collection_machine_info = "debian12_ko"  # 采集机器信息

    pcap_database_handler = PcapToDatabaseHandler(
        db_config,
        my_base_table_name,
        test_pcap_file,
        test_json_file,
        protocol_type,
        accessed_website_name,
        collection_machine_info,
    )

    initialize_database_schema(db_config, my_base_table_name)
    pcap_database_handler.pcap_to_database()
