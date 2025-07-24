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

import os
import warnings
from datetime import datetime
from typing import Any, Dict, List, Tuple, Union

# 从父类和自定义模块导入必要的组件
from pypcaptools.pcaphandler import PcapHandler
from pypcaptools.TrafficDB.FlowDB import FlowDB
from pypcaptools.TrafficDB.TraceDB import TraceDB
from pypcaptools.util import (  # 假设 DBConfig 是一个 Dict[str, Any] 类型别名
    DBConfig,
    serialization,
)

# 定义 trace 表中每个流的最大数据包数量，用于限制序列化数据的大小
TRACE_MAX_PKT_NUM = 600000


class PcapToDatabaseHandler(PcapHandler):
    """
    继承自 PcapHandler，实现将 PCAP 文件中的流量数据存入数据库。
    支持 trace（整个 PCAP 文件作为一个 trace）和 flow（PCAP 中的每个独立流）
    两种粒度的数据存储。
    """

    def __init__(
        self,
        db_config: DBConfig,  # 数据库连接配置
        input_pcap_file: str,  # 输入的 PCAP 文件路径
        protocol: str,  # 协议类型（例如：http, dns, tls 等应用层协议）
        table_name: str,  # 存储流量数据的数据库表名
        accessed_website: str,  # 访问的网站或应用名称
        collection_machine: str = "",  # 采集流量的机器信息（可选）
        comment: str = "",  # 备注信息（可选）
    ):
        """
        初始化 PcapToDatabaseHandler 对象。

        Args:
            db_config: 数据库配置信息，通常包含 host, port, user, password, database 等键。
            input_pcap_file: 待处理的 PCAP 文件在本地的路径。
            protocol: 流量所属的应用层协议类型。
            table_name: 数据库中用于存储流量数据的表名。
            accessed_website: 流量访问的目标网站或应用标识。
            collection_machine: 采集此 PCAP 文件的机器名称或标识。
            comment: 关于此 PCAP 或采集任务的额外备注。
        """
        # 调用父类 PcapHandler 的构造函数进行初始化
        super().__init__(input_pcap_file)

        self.db_config = db_config
        self.protocol = protocol
        self.accessed_website = accessed_website
        self.collection_machine = collection_machine
        self.pcap_path = input_pcap_file  # 存储原始 PCAP 文件路径
        self.comment = comment
        self.table = table_name  # 数据库表名

    def _get_db_connection_params(self) -> Dict[str, Any]:
        """
        从数据库配置中提取连接参数。

        Returns:
            一个包含数据库连接参数的字典。
        """
        return {
            "host": self.db_config.get("host"),
            "user": self.db_config.get("user"),
            "port": self.db_config.get("port"),
            "password": self.db_config.get("password"),
            "database": self.db_config.get("database"),
            # "table" 并不是 FlowDB/TraceDB 构造函数直接需要的参数，它会在实例化时传入
        }

    def _save_flows_to_database(
        self,
        tcp_streams: Dict[str, Any],
        min_packet_num: int = 3,
        trace_id: int = -1,
        first_capture_time: float = 0.0,
    ):
        """
        将解析和分割好的 TCP 流数据作为 Flow 记录存入数据库。
        此方法可以用于独立存储 Flow，或与 Trace 关联存储。

        Args:
            tcp_streams: 一个字典，键为五元组字符串，值为该流的详细信息（包含 packets 和 sni）。
                         例如：{"src_ip_src_port_dst_ip_dst_port_protocol": {"packets": [...], "sni": "..."}}
            min_packet_num: 过滤阈值，只有数据包数量大于此值的流才会被存储。
            trace_id: 如果此 Flow 记录需要与某个 Trace 记录关联，则提供 Trace 的 ID；
                      如果为 -1，表示只存储 Flow 记录，不关联 Trace。
            first_capture_time: 如果关联 Trace，提供 Trace 中第一个数据包的Unix时间戳，用于计算相对时间。
                                如果不关联 Trace，此参数可能不被使用或默认为0。
        """
        # 如果 trace_id 为 0，表示没有有效的 Trace 需要关联，或者 Trace 存储失败，则不继续存储 Flow
        if trace_id == 0:  # 假设 trace_id=0 是无效 ID
            warnings.warn(
                "trace_id 为 0，跳过存储 Flow 到数据库。", category=UserWarning
            )
            return

        db_params = self._get_db_connection_params()

        # 根据 trace_id 选择实例化 FlowDB 或 TraceDB (此处应为 FlowDB)
        # Note: TraceDB 主要是用于存储整个 pcap 的元数据和流量序列，
        # 而 FlowDB 用于存储每个独立 TCP/UDP 流的元数据和流量序列。
        # 此方法是 _save_flows_to_database，因此总是实例化 FlowDB。
        try:
            traffic_db = TraceDB(
                db_params["host"],
                db_params["port"],
                db_params["user"],
                db_params["password"],
                db_params["database"],
                self.table,  # FlowDB 的表名
            )
            traffic_db.connect()
        except Exception as e:
            warnings.warn(f"连接 FlowDB 数据库失败: {e}", category=UserWarning)
            return

        for stream_key, stream_info in tcp_streams.items():
            # 检查流的数据包数量是否达到最小阈值
            if len(stream_info["packets"]) <= min_packet_num:
                continue

            flow_record: Dict[str, Any] = {}
            if trace_id != -1:
                flow_record["trace_id"] = trace_id  # 关联 Trace ID

            # 记录数据入库时间
            flow_record["entry_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # 确定当前流的捕获起始时间
            # 如果提供了 first_capture_time (通常来自 Trace 的第一个包)，则使用它作为相对时间基准；
            # 否则，使用当前流的第一个包的时间戳。
            flow_first_time = stream_info["packets"][0][
                0
            ]  # 当前流的第一个包的绝对时间戳
            capture_base_time = (
                first_capture_time if first_capture_time != 0.0 else flow_first_time
            )

            flow_record["capture_time"] = datetime.fromtimestamp(
                capture_base_time
            ).strftime("%Y-%m-%d %H:%M:%S")

            # 解析五元组信息
            try:
                (
                    flow_record["source_ip"],
                    flow_record["source_port"],
                    flow_record["destination_ip"],
                    flow_record["destination_port"],
                    flow_record["transport_protocol"],
                ) = stream_key.split("_")
                flow_record["source_port"] = int(flow_record["source_port"])
                flow_record["destination_port"] = int(flow_record["destination_port"])
            except ValueError:
                warnings.warn(
                    f"解析流标识符 '{stream_key}' 失败，跳过此流。",
                    category=UserWarning,
                )
                continue

            # 初始化列表，存储相对时间戳和负载长度
            relative_timestamps: List[str] = []
            payload_lengths: List[str] = []

            for packet in stream_info["packets"]:
                timestamp, payload_str, _ = packet  # _ 表示 packet_num，此处不需要
                relative_time = timestamp - capture_base_time
                relative_timestamps.append(
                    f"{relative_time:.6f}"
                )  # 保留6位小数，表示微秒级精度
                payload_lengths.append(payload_str)

            # 序列化后存入数据库，并限制最大包数
            flow_record["timestamp"] = serialization(
                relative_timestamps[
                    :TRACE_MAX_PKT_NUM
                ]  # 使用 TRACE_MAX_PKT_NUM 限制长度
            )
            flow_record["payload"] = serialization(
                payload_lengths[:TRACE_MAX_PKT_NUM]  # 使用 TRACE_MAX_PKT_NUM 限制长度
            )

            flow_record["protocol"] = self.protocol
            flow_record["accessed_website"] = self.accessed_website
            flow_record["packet_length"] = len(payload_lengths)  # 总数据包数量

            # 统计非空负载的数据包数量
            flow_record["packet_length_no_payload"] = sum(
                1 for item in payload_lengths if item != "+0" and item != "-0"
            )

            flow_record["collection_machine"] = self.collection_machine
            flow_record["pcap_path"] = self.pcap_path
            flow_record["sni"] = stream_info.get(
                "sni", ""
            )  # 获取 SNI，如果不存在则为空字符串

            try:
                traffic_db.add_traffic(flow_record)  # 将 Flow 记录添加到数据库
            except Exception as e:
                warnings.warn(
                    f"向 FlowDB 添加流量记录失败 (流: {stream_key}): {e}",
                    category=UserWarning,
                )

        try:
            traffic_db.close()  # 关闭数据库连接
        except Exception as e:
            warnings.warn(f"关闭 FlowDB 连接失败: {e}", category=UserWarning)

    def flow_to_database(
        self, min_packet_num: int = 3, tcp_from_first_packet: bool = False
    ):
        """
        仅将 PCAP 文件分割后的 TCP 流以 flow 为单位存入数据库，不保留 trace 信息。
        此方法适用于只需要存储独立流量会话的场景。

        Args:
            min_packet_num: 最小包数过滤阈值，只有数据包数量大于此值的流才会被存储。
            tcp_from_first_packet: 如果为 True，对于 TCP 流，只保留以 SYN 握手包开始的流。
        """
        # 调用父类方法处理 PCAP 文件，获取分割后的 TCP 流数据
        tcp_streams = self._process_pcap_file(tcp_from_first_packet)
        if tcp_streams is None:
            warnings.warn(
                "未从 PCAP 文件中解析到任何有效流量流，无法存储 Flow。",
                category=UserWarning,
            )
            return

        # 调用内部方法将流数据保存到数据库中（不关联 Trace）
        self._save_flows_to_database(tcp_streams, min_packet_num)
        print(f"成功将 {len(tcp_streams)} 个有效流存储到数据库 (仅 Flow)。")

    def _save_trace_to_database(
        self, flow_num: int
    ) -> Union[Tuple[int, float], Tuple[None, None]]:
        """
        将整个 PCAP 文件作为一个 Trace 记录存入数据库。
        此方法会读取整个 PCAP 文件的所有数据包，并将其序列化为 Trace 记录。

        Args:
            flow_num: 此 Trace 中包含的独立 Flow 数量。

        Returns:
            一个元组 (trace_id, first_time)，其中 trace_id 是新插入的 Trace 记录的 ID，
            first_time 是整个 Trace 中第一个数据包的 Unix 时间戳。
            如果存储失败，则返回 (None, None)。
        """
        db_params = self._get_db_connection_params()

        try:
            traffic_db = TraceDB(
                db_params["host"],
                db_params["port"],
                db_params["user"],
                db_params["password"],
                db_params["database"],
                self.table,  # TraceDB 的表名
            )
            traffic_db.connect()
        except Exception as e:
            warnings.warn(f"连接 TraceDB 数据库失败: {e}", category=UserWarning)
            return None, None

        trace_record: Dict[str, Any] = {}

        # 获取未分割的流量数据（整个 PCAP 文件作为一个流）
        transport_protocol_type, whole_stream_packets = (
            self._process_pcap_file_nosplit()
        )
        if whole_stream_packets is None or not whole_stream_packets:
            warnings.warn(
                "未从 PCAP 文件中解析到任何数据包，无法存储 Trace。",
                category=UserWarning,
            )
            try:
                traffic_db.close()
            except:
                pass
            return None, None

        trace_record["transport_protocol"] = transport_protocol_type
        trace_record["entry_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 确定 Trace 的捕获起始时间（即整个 PCAP 文件的第一个包的时间）
        first_time = whole_stream_packets[0][0]  # 第一个包的绝对时间戳
        trace_record["capture_time"] = datetime.fromtimestamp(first_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # 计算相对时间戳和负载长度序列
        relative_timestamps: List[str] = []
        payload_lengths: List[str] = []
        for packet in whole_stream_packets:
            timestamp, payload_str, _ = packet  # _ 表示 packet_num，此处不需要
            relative_time = timestamp - first_time
            relative_timestamps.append(f"{relative_time:.6f}")
            payload_lengths.append(payload_str)

        trace_record["flownum"] = flow_num  # 记录此 Trace 中包含的 Flow 数量

        # 序列化并存储时间戳和负载，并限制最大包数
        trace_record["timestamp"] = serialization(
            relative_timestamps[:TRACE_MAX_PKT_NUM]
        )
        trace_record["payload"] = serialization(payload_lengths[:TRACE_MAX_PKT_NUM])

        trace_record["protocol"] = self.protocol
        trace_record["accessed_website"] = self.accessed_website
        trace_record["packet_length"] = len(payload_lengths)  # 总数据包数量

        # 统计非空负载的数据包数量
        trace_record["packet_length_no_payload"] = sum(
            1 for item in payload_lengths if item != "+0" and item != "-0"
        )

        trace_record["collection_machine"] = self.collection_machine
        trace_record["pcap_path"] = self.pcap_path

        trace_id = None
        try:
            trace_id = traffic_db.add_trace(trace_record)  # 将 Trace 记录添加到数据库
        except Exception as e:
            warnings.warn(f"向 TraceDB 添加 Trace 记录失败: {e}", category=UserWarning)
        finally:
            try:
                traffic_db.close()  # 关闭数据库连接
            except:
                pass

        return trace_id, first_time

    def pcap_to_database(
        self, min_packet_num: int = 3, tcp_from_first_packet: bool = True
    ):
        """
        同时将 PCAP 文件以 trace 和 flow 两种粒度存入数据库。
        此方法会先将整个 PCAP 文件作为 Trace 记录写入数据库，获取 Trace ID 和捕获起始时间；
        然后，再将 PCAP 文件分割为独立的 Flow 记录，并使用获得的 Trace ID 进行关联。

        Args:
            min_packet_num: 最小包数过滤阈值，只有数据包数量大于此值的流才会被存储到 Flow 表。
            tcp_from_first_packet: 如果为 True，对于 TCP 流，只保留以 SYN 握手包开始的流。
        """
        # 1. 解析 PCAP 文件，获取分割后的 TCP 流数据
        tcp_streams = self._process_pcap_file(tcp_from_first_packet)
        if tcp_streams is None:
            warnings.warn(
                "未从 PCAP 文件中解析到任何有效流量流，跳过 Trace 和 Flow 存储。",
                category=UserWarning,
            )
            return

        # 过滤掉不满足最小包数要求的流，计算实际会入库的 Flow 数量
        effective_flow_count = sum(
            1
            for stream_info in tcp_streams.values()
            if len(stream_info["packets"]) > min_packet_num
        )

        # 2. 将整个 PCAP 文件作为 Trace 记录存入数据库，获取 Trace ID 和第一个包的时间戳
        print(f"开始存储 Trace 记录到数据库，包含 {effective_flow_count} 个 Flow。")
        trace_id, first_capture_time = self._save_trace_to_database(
            effective_flow_count
        )

        if trace_id is None:
            warnings.warn("Trace 记录存储失败，停止存储 Flow。", category=UserWarning)
            return

        print(f"Trace 记录存储成功，Trace ID: {trace_id}")

        # 3. 将分割后的 Flow 记录存入数据库，并关联 Trace ID
        print(f"开始存储 Flow 记录到数据库，关联 Trace ID: {trace_id}。")
        self._save_flows_to_database(
            tcp_streams, min_packet_num, trace_id, first_capture_time
        )
        print("Flow 记录存储完成。")


if __name__ == "__main__":
    # --- 示例数据库配置 ---
    # 请根据您的实际数据库环境修改以下配置信息
    db_config: DBConfig = {
        "host": "localhost",  # 数据库主机名或IP地址
        "port": 3306,  # 数据库端口
        "user": "root",  # 数据库用户名
        "password": "aimafan",  # 数据库密码
        "database": "WebsitesTraffic250723",  # 数据库名称
    }

    # --- 示例 PCAP 文件路径 ---
    # 请确保此路径指向一个实际存在的 PCAP 文件，或在运行前创建此文件
    # 例如，您可以下载一个测试用的 PCAP 文件到当前目录
    test_pcap_file = (
        "http_20250722074421_141.164.58.43_jp_google.com.pcap"  # 假设您有一个这样的文件
    )

    # --- 测试数据参数 ---
    protocol_type = "http"  # 示例协议类型
    trace_table_name = flow_table_name = "direct_back"  # 存储 Flow 数据的表名

    accessed_website_name = "google.com"  # 访问的网站
    collection_machine_info = "debian12_jp"  # 采集机器信息
    test_comment = "Test run for PcapToDatabaseHandler optimization"  # 备注

    # 检查测试 PCAP 文件是否存在
    if not os.path.exists(test_pcap_file):
        print(
            f"错误: 测试 PCAP 文件 '{test_pcap_file}' 不存在。请提供一个有效的 PCAP 文件路径。"
        )
        print("您可以通过运行 pcaphandler.py 模块中的示例生成一个测试 PCAP 文件。")
    else:
        print(f"--- 开始处理 PCAP 文件: {test_pcap_file} ---")

        # --- 2. 测试同时存储 Trace 和 Flow 数据到数据库 ---
        print("\n--- 2. 测试同时存储 Trace 和 Flow 数据到数据库 ---")
        try:
            # 为 Trace 和 Flow 分别创建处理对象，如果它们使用不同的表名
            pcap_full_db_handler = PcapToDatabaseHandler(
                db_config,
                test_pcap_file,
                protocol_type,
                trace_table_name,  # 为 Trace 表指定名称 (这个会传给 TraceDB)
                accessed_website_name,
                collection_machine_info,
                test_comment,
            )
            # 调用 pcap_to_database 方法，同时存储 Trace 和 Flow，要求 TCP 流从 SYN 开始
            pcap_full_db_handler.pcap_to_database(
                min_packet_num=3, tcp_from_first_packet=True
            )
            print("Trace 和 Flow 数据同时存储测试完成。")
        except Exception as e:
            print(f"同时存储 Trace 和 Flow 数据到数据库失败: {e}")
            warnings.warn(
                f"测试失败: 同时存储 Trace 和 Flow 数据到数据库: {e}",
                category=UserWarning,
            )

        print("\n--- 所有数据库操作测试完成 ---")
