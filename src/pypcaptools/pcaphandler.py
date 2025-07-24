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
from typing import Any, Dict, List, Tuple, Union

import dpkt
import scapy.all as scapy
from dpkt.utils import inet_to_str

# 定义常量，用于SNI提取的限制
MAX_PKT_FOR_SNI_EXTRACT = 30  # 每个流在尝试提取SNI时，最多处理的数据包数量
MAX_BYTES_FOR_SNI_EXTRACT = 8192  # 每个流在尝试提取SNI时，最多累积的字节数


def extract_sni(tcp_data: bytes) -> Union[str, None]:
    """
    尝试从TLS ClientHello数据中提取SNI（Server Name Indication）字段。
    此函数通过手动解析TLS握手协议的字节流来查找SNI扩展。

    Args:
        tcp_data: 包含TLS ClientHello信息的TCP负载数据（原始字节）。

    Returns:
        如果成功提取到SNI，则返回SNI字符串；否则返回None。
    """
    try:
        # 1. 检查TLS记录头：确保数据长度足够进行初步判断
        # TLS记录头通常为5字节：ContentType(1) + Version(2) + Length(2)
        if len(tcp_data) < 5:
            return None  # 数据太短，无法判断TLS记录头

        # 检查Content Type是否为TLS握手记录 (Handshake, 0x16)
        if tcp_data[0] != 0x16:
            return None
        # 检查TLS主版本号 (Version: TLSv1.x，通常是0x03)
        if tcp_data[1] != 0x03:
            return None

        # 读取TLS记录长度 (Length)，高位在前 (大端字节序)
        tls_record_len = struct.unpack(">H", tcp_data[3:5])[0]
        # 确保收到的数据完整覆盖整个TLS记录
        if len(tcp_data) < 5 + tls_record_len:
            return None  # 数据不完整，等待更多数据

        # 2. 检查Client Hello握手消息：
        # Client Hello消息在TLS记录头之后，偏移量为5
        # 第6个字节是Handshake Type (Client Hello, 0x01)
        if tcp_data[5] != 0x01:
            return None

        # 读取握手消息长度 (Length)，3字节，高位在前 (需要补一个字节才能用>I解包)
        # Client Hello消息的长度字段从偏移量6开始，持续3个字节
        handshake_msg_len = struct.unpack(">I", b"\x00" + tcp_data[6:9])[0]
        # 确保收到的数据完整覆盖整个Client Hello消息
        if len(tcp_data) < 9 + handshake_msg_len:
            return None  # 数据不完整，等待更多数据

        # 3. 解析Client Hello消息的各个字段，跳到Extensions部分
        # 当前解析位置的索引，从Client Hello消息的随机数之后开始
        # 初始跳过：Handshake Type (1字节) + Length (3字节) + Protocol Version (2字节) + Random (32字节)
        idx = 9  # 指向 ClientHello 剩余内容的起始位置 (即Protocol Version之后)

        # 跳过 Session ID (Session ID Length 1字节 + Session ID Value 变长)
        if (
            len(tcp_data) < idx + 34 + 1
        ):  # 34字节是ClientHello的Protocol Version(2)和Random(32)长度
            return None
        session_id_len = tcp_data[idx + 34]  # Session ID 长度字段
        idx += 35 + session_id_len  # 跳过 Session ID 长度字段和 Session ID 值

        # 跳过 Cipher Suites (Cipher Suites Length 2字节 + Cipher Suites Value 变长)
        if len(tcp_data) < idx + 2:
            return None
        cipher_suites_len = struct.unpack(">H", tcp_data[idx : idx + 2])[
            0
        ]  # Cipher Suites 长度
        idx += 2 + cipher_suites_len  # 跳过 Cipher Suites 长度字段和 Cipher Suites 值

        # 跳过 Compression Methods (Compression Methods Length 1字节 + Compression Methods Value 变长)
        if len(tcp_data) < idx + 1:
            return None
        compression_methods_len = tcp_data[idx]  # 压缩方法长度
        idx += 1 + compression_methods_len  # 跳过 压缩方法长度字段和 压缩方法值

        # 4. 解析 Extensions 字段
        if len(tcp_data) < idx + 2:
            return None
        extensions_len = struct.unpack(">H", tcp_data[idx : idx + 2])[
            0
        ]  # 扩展字段总长度 (2字节)
        idx += 2  # 跳过扩展字段总长度字段

        # 扩展字段的实际结束位置
        current_ext_parse_end_idx = idx + extensions_len
        if len(tcp_data) < current_ext_parse_end_idx:
            return None  # 实际数据长度不足以包含所有扩展字段

        # 遍历所有扩展字段
        while (
            idx + 4 <= current_ext_parse_end_idx
        ):  # 确保至少有扩展类型 (2字节) 和扩展长度 (2字节)
            if len(tcp_data) < idx + 4:  # 边界检查
                return None
            ext_type = struct.unpack(">H", tcp_data[idx : idx + 2])[
                0
            ]  # 扩展类型 (Type)
            ext_len = struct.unpack(">H", tcp_data[idx + 2 : idx + 4])[
                0
            ]  # 扩展长度 (Length)
            idx += 4  # 跳过扩展类型和长度字段

            # 检查当前扩展的实际数据是否完整
            if len(tcp_data) < idx + ext_len:  # 边界检查
                return None

            if ext_type == 0x00:  # Server Name 扩展类型 (TLS SNI扩展的类型码是0x0000)
                # 解析Server Name List
                if ext_len < 2:  # Server Name List 至少需要2字节表示List长度
                    idx += ext_len  # 跳过当前扩展
                    continue

                # Server Name List 的总长度 (2字节)
                sni_list_len = struct.unpack(">H", tcp_data[idx : idx + 2])[0]
                pos = idx + 2  # 指向Server Name List的实际内容

                # 确保 sni_list_len 不会超出当前扩展的实际范围
                if pos + sni_list_len > idx + ext_len:
                    return None  # 列表长度声明超出扩展实际范围

                end_sni_list = pos + sni_list_len  # Server Name List的结束位置

                while (
                    pos + 3 <= end_sni_list
                ):  # 确保至少有 Name Type (1字节) + Name Length (2字节)
                    name_type = tcp_data[pos]  # 名称类型 (0x00 表示 hostname)
                    name_len = struct.unpack(">H", tcp_data[pos + 1 : pos + 3])[
                        0
                    ]  # 名称长度
                    pos += 3  # 跳过名称类型和名称长度字段

                    # 检查名称数据是否完整
                    if pos + name_len > end_sni_list:  # 边界检查
                        return None

                    if name_type == 0:  # host_name (主机名类型是0x00)
                        sni = tcp_data[pos : pos + name_len].decode(
                            errors="ignore"  # 提取SNI字符串，忽略解码错误
                        )
                        return sni  # 找到SNI后立即返回

                    pos += name_len  # 跳到下一个Server Name条目
                # 如果遍历完Server Name List没有找到SNI或数据不完整，则跳出并继续处理下一个扩展
                # 因为Server Name扩展已经处理完毕，即使没找到SNI也跳出当前扩展的内部循环
                break

            idx += ext_len  # 跳过当前扩展，处理下一个
    except Exception as e:
        # 捕获解析过程中可能出现的任何异常，并返回None
        # print(f"SNI提取错误: {e}") # 可用于调试
        return None

    return None  # 遍历所有扩展后仍未找到SNI


class PcapHandler:
    """
    PcapHandler类用于处理PCAP文件，解析其中的网络流量数据，并按特定方式进行分流。
    支持将处理后的流量数据保存为PCAP或JSON格式。
    """

    def __init__(self, input_pcap_file: str):
        """
        初始化PcapHandler对象。

        Args:
            input_pcap_file: 输入的PCAP文件路径。
        """
        self.datalink = 1  # 数据链路层类型，默认为以太网 (DLT_EN10MB=1)
        self.input_pcap_file = input_pcap_file
        # 预加载所有Scapy数据包，以便在保存PCAP时按索引访问，提高效率
        self._scapy_packets = self._load_scapy_packets()

    def _load_scapy_packets(self) -> scapy.PacketList:
        """
        使用Scapy预加载PCAP文件中的所有数据包，以便后续按索引访问。
        这可以避免在保存PCAP文件时重复读取源文件，显著提高效率。

        Returns:
            一个scapy.PacketList对象，包含PCAP文件中的所有数据包。
            如果文件不存在、为空或读取失败，则返回空的PacketList。
        """
        if (
            not os.path.exists(self.input_pcap_file)
            or os.path.getsize(self.input_pcap_file) <= 10
        ):
            warnings.warn(
                f"PCAP文件 '{self.input_pcap_file}' 不存在或为空（小于等于10字节），跳过加载。",
                category=UserWarning,
            )
            return scapy.PacketList()  # 返回空列表

        try:
            return scapy.rdpcap(self.input_pcap_file)
        except Exception as e:
            warnings.warn(
                f"无法使用Scapy读取PCAP文件 '{self.input_pcap_file}': {e}",
                category=UserWarning,
            )
            return scapy.PacketList()

    def _get_ip_packet(self, pkt_data: bytes) -> Union[dpkt.ip.IP, None]:
        """
        根据数据链路层类型，从原始数据包字节中提取IP层数据。

        Args:
            pkt_data: 原始数据包的字节数据。

        Returns:
            如果成功提取到IP层对象，则返回dpkt.ip.IP实例；否则返回None。
        """
        try:
            if self.datalink == dpkt.pcap.DLT_EN10MB:  # 1: Ethernet (以太网)
                eth = dpkt.ethernet.Ethernet(pkt_data)
                return eth.data if isinstance(eth.data, dpkt.ip.IP) else None
            elif (
                self.datalink == 239
            ):  # 239: DLT_IEEE802_11_RADIOTAP (Radiotap, Wi-Fi捕获中常见)
                # 通常Radiotap头之后是Ethernet帧，需要解析两层
                eth = dpkt.ethernet.Ethernet(
                    pkt_data
                )  # 尝试直接解析为以太网帧，有时有效
                return eth.data if isinstance(eth.data, dpkt.ip.IP) else None
            elif self.datalink == dpkt.pcap.DLT_RAW or self.datalink in (228, 229):
                # 101: DLT_RAW (原始IP)；228, 229：可能是特定系统下的原始IP或其他直接包含IP的数据
                return dpkt.ip.IP(pkt_data)
            elif (
                self.datalink == dpkt.pcap.DLT_LINUX_SLL2
            ):  # 276: Linux Cooked Capture v2
                sll2 = dpkt.sll2.SLL2(pkt_data)
                return sll2.data if isinstance(sll2.data, dpkt.ip.IP) else None
            # 可以根据需要添加更多DLT类型的处理
            else:
                warnings.warn(
                    f"无法识别的数据链路层协议 (DLT: {self.datalink})，跳过该数据包。",
                    category=UserWarning,
                )
                return None
        except dpkt.dpkt.NeedData:
            # 数据包不完整，无法解析
            return None
        except Exception as e:
            warnings.warn(
                f"解析IP数据包失败 (DLT: {self.datalink}): {e}", category=UserWarning
            )
            return None

    def _get_payload_size(
        self, ip_packet: dpkt.ip.IP, protocol_text: str
    ) -> Union[int, None]:
        """
        计算IP数据包中传输层（TCP/UDP）的有效负载长度。

        Args:
            ip_packet: IP层对象 (dpkt.ip.IP)。
            protocol_text: 协议类型字符串，"TCP"或"UDP"。

        Returns:
            负载长度（字节），如果协议不支持或数据包结构异常则返回None。
        """
        # IP头部长度 (单位：4字节，所以需要乘以4)
        ip_header_length = ip_packet.hl * 4
        # IP总长度，包括IP头部和负载 (单位：字节)
        ip_total_length = ip_packet.len

        transport_header_length = 0
        if protocol_text == "TCP":
            # TCP头部长度 (单位：4字节，所以需要乘以4)
            # 检查ip_packet.data是否确实是TCP类型
            if not isinstance(ip_packet.data, dpkt.tcp.TCP):
                return None
            transport_header_length = ip_packet.data.off * 4
        elif protocol_text == "UDP":
            # UDP头部长度固定为8字节
            # 检查ip_packet.data是否确实是UDP类型
            if not isinstance(ip_packet.data, dpkt.udp.UDP):
                return None
            transport_header_length = 8
        else:
            return None  # 不支持其他传输层协议的负载计算

        # 负载长度 = IP总长度 - IP头部长度 - 传输层头部长度
        payload_len = ip_total_length - ip_header_length - transport_header_length
        return payload_len if payload_len >= 0 else 0  # 确保负载长度不为负值

    def _read_dpkt_pcap(self) -> Union[dpkt.pcap.Reader, dpkt.pcapng.Reader, None]:
        """
        尝试打开PCAP文件，并以dpkt.pcap.Reader或dpkt.pcapng.Reader的形式返回。
        此方法封装了dpkt读取pcap/pcapng文件的逻辑。

        Returns:
            dpkt.pcap.Reader或dpkt.pcapng.Reader实例，如果文件为空或无法打开则返回None。
        Raises:
            TypeError: 如果无法以任何已知格式打开或解析PCAP文件。
        """
        if (
            not os.path.exists(self.input_pcap_file)
            or os.path.getsize(self.input_pcap_file) <= 10
        ):
            warnings.warn(
                f"PCAP文件 '{self.input_pcap_file}' 不存在或为空（小于等于10字节），跳过处理。",
                category=UserWarning,
            )
            return None

        f = None  # 初始化文件句柄
        try:
            f = open(self.input_pcap_file, "rb")
            try:
                pkts = dpkt.pcap.Reader(f)  # 尝试按PCAP格式读取
            except ValueError:
                f.seek(0)  # 如果不是pcap格式，重置文件指针
                pkts = dpkt.pcapng.Reader(f)  # 尝试按PCAPNG格式读取
            return pkts
        except Exception as e:
            if f:
                f.close()  # 确保文件关闭
            raise TypeError(f"无法打开或解析PCAP文件 '{self.input_pcap_file}': {e}")

    def _process_pcap_file(
        self, tcp_from_first_packet: bool = True
    ) -> Union[Dict[str, Any], None]:
        """
        解析PCAP文件，将网络流量数据按五元组（源IP、源端口、目的IP、目的端口、协议）进行分流。
        支持TCP和UDP协议。

        Args:
            tcp_from_first_packet: 如果为True，对于TCP流，只保留以SYN握手包开始的流。

        Returns:
            一个字典，键为五元组字符串（如 "srcip_srcport_dstip_dstport_protocol"），
            值为包含该流数据包信息的字典（包括时间戳、负载大小、包编号和SNI）。
            如果PCAP文件为空或处理失败，则返回None。
        """
        # 存储分流后的数据，键为五元组字符串
        # 结构示例: {"五元组": {"packets": [[时间戳, "±负载", 包号], ...], "sni": "example.com"}}
        flow_streams: Dict[str, Dict[str, Any]] = {}

        # 用于SNI提取的辅助数据结构
        stream_data_for_sni = defaultdict(
            bytes
        )  # 存储每个流的累计TCP数据，以便进行SNI解析
        stream_pkt_count_for_sni = defaultdict(
            int
        )  # 存储每个流中用于SNI解析的数据包数量
        # 记录已完成SNI提取（或达到提取限制）的流，避免重复处理
        sni_extraction_completed_flows = set()

        dpkt_reader = self._read_dpkt_pcap()
        if dpkt_reader is None:
            return None

        self.datalink = dpkt_reader.datalink()  # 获取PCAP文件的数据链路层类型

        packet_number = -1  # 初始化数据包编号，从0开始计数

        try:
            for timestamp, raw_packet_data in dpkt_reader:
                packet_number += 1

                # 提取IP层数据
                ip_packet = self._get_ip_packet(raw_packet_data)
                if not isinstance(ip_packet, dpkt.ip.IP):
                    warnings.warn(
                        f"包 {packet_number}: 非IP数据包，忽略。", category=UserWarning
                    )
                    continue

                # 判断传输层协议类型 (只处理TCP或UDP)
                transport_protocol_text: Union[str, None] = None
                transport_packet: Union[dpkt.tcp.TCP, dpkt.udp.UDP, None] = None

                if isinstance(ip_packet.data, dpkt.udp.UDP):
                    transport_protocol_text = "UDP"
                    transport_packet = ip_packet.data
                elif isinstance(ip_packet.data, dpkt.tcp.TCP):
                    transport_protocol_text = "TCP"
                    transport_packet = ip_packet.data
                else:
                    warnings.warn(
                        f"包 {packet_number}: 非TCP/UDP数据包，忽略。",
                        category=UserWarning,
                    )
                    continue

                # 获取传输层负载大小
                payload_size = self._get_payload_size(
                    ip_packet, transport_protocol_text
                )
                if payload_size is None:
                    warnings.warn(
                        f"包 {packet_number}: 无法获取负载大小，忽略。",
                        category=UserWarning,
                    )
                    continue

                # 提取源/目的IP和端口
                src_port, dst_port = transport_packet.sport, transport_packet.dport
                src_ip, dst_ip = inet_to_str(ip_packet.src), inet_to_str(ip_packet.dst)

                # 构造五元组标识，用于唯一标识一个会话流
                # 统一格式：源IP_源端口_目的IP_目的端口_协议
                five_tuple_forward = (
                    f"{src_ip}_{src_port}_{dst_ip}_{dst_port}_{transport_protocol_text}"
                )
                five_tuple_backward = (
                    f"{dst_ip}_{dst_port}_{src_ip}_{src_port}_{transport_protocol_text}"
                )

                # 检查数据包属于哪个方向的现有流，或创建一个新流
                current_stream_key: str
                direction_symbol: (
                    str  # "+" 表示正向 (来自src_ip), "-" 表示反向 (来自dst_ip)
                )

                if five_tuple_forward in flow_streams:
                    current_stream_key = five_tuple_forward
                    direction_symbol = "+"
                elif five_tuple_backward in flow_streams:
                    current_stream_key = five_tuple_backward
                    direction_symbol = "-"
                else:
                    # 如果是新流，且要求TCP流必须从SYN包开始，则进行检查
                    if transport_protocol_text == "TCP" and tcp_from_first_packet:
                        # SYN标志位是TCP flags中的第二个位 (dpkt.tcp.TH_SYN=0x02)
                        # TH_ACK是0x10，如果是SYN-ACK (0x12) 则不满足纯SYN的条件
                        if not (transport_packet.flags & dpkt.tcp.TH_SYN) or (
                            transport_packet.flags & dpkt.tcp.TH_ACK
                        ):
                            continue  # 不是纯SYN包（例如是SYN-ACK或ACK），忽略此流的第一个包

                    current_stream_key = five_tuple_forward  # 新流以正向五元组为键
                    direction_symbol = "+"
                    # 初始化新流的数据结构
                    flow_streams[current_stream_key] = {
                        "packets": [],  # 存储 [时间戳, "±负载", 包编号]
                        "sni": None,  # 用于存储提取到的SNI
                    }

                # 将当前数据包信息添加到对应的流中
                flow_streams[current_stream_key]["packets"].append(
                    [timestamp, f"{direction_symbol}{payload_size}", packet_number]
                )

                # SNI 提取逻辑 (只处理 DST 端口为 443 的 TCP 客户端数据包)
                if (
                    transport_protocol_text == "TCP"
                    and dst_port == 443
                    and direction_symbol == "+"  # 确保是客户端发往服务器的包
                    and len(transport_packet.data) > 0  # 确保有TCP负载
                    and current_stream_key not in sni_extraction_completed_flows
                ):  # 避免重复提取
                    stream_data_for_sni[current_stream_key] += transport_packet.data
                    stream_pkt_count_for_sni[current_stream_key] += 1

                    # 设置提取SNI的限制，避免内存溢出或不必要的计算
                    if (
                        stream_pkt_count_for_sni[current_stream_key]
                        > MAX_PKT_FOR_SNI_EXTRACT
                        or len(stream_data_for_sni[current_stream_key])
                        > MAX_BYTES_FOR_SNI_EXTRACT
                    ):
                        # 达到限制，清除该流的SNI提取相关数据并标记为已完成
                        del stream_data_for_sni[current_stream_key]
                        del stream_pkt_count_for_sni[current_stream_key]
                        sni_extraction_completed_flows.add(current_stream_key)
                        continue  # 继续处理下一个数据包

                    # 尝试提取SNI
                    sni = extract_sni(stream_data_for_sni[current_stream_key])
                    if sni:
                        flow_streams[current_stream_key]["sni"] = sni
                        # 成功提取SNI，清除数据并标记为已完成
                        del stream_data_for_sni[current_stream_key]
                        del stream_pkt_count_for_sni[current_stream_key]
                        sni_extraction_completed_flows.add(current_stream_key)

        except dpkt.dpkt.NeedData:
            # 捕获部分PCAP文件读取异常，通常是数据包不完整，跳过即可
            pass
        except Exception as e:
            warnings.warn(f"处理PCAP文件时发生未知错误: {e}", category=UserWarning)
        finally:
            # 确保文件句柄在处理完毕或发生异常时关闭
            if hasattr(dpkt_reader, "f") and not dpkt_reader.f.closed:
                dpkt_reader.f.close()

        return flow_streams

    def _process_pcap_file_nosplit(self) -> Union[Tuple[str, List[Any]], None]:
        """
        解析PCAP文件，但不进行分流，所有数据包被视为一个整体流（单流）。
        主要用于生成整个PCAP文件的负载长度序列。

        Returns:
            一个元组 (协议类型, 格式化后的数据包列表)。
            协议类型可以是 "TCP", "UDP", "mix" (混合), 或 "" (无有效数据包)。
            数据包列表包含 [时间戳, "±负载", 包编号] 的信息。
            如果PCAP文件为空或处理失败，则返回None。
        """
        single_stream_data: List[List[Any]] = []  # 存储 [时间戳, "±负载", 包编号]
        first_src_ip: str = ""  # 用于标记正向流的第一个数据包的源IP
        protocol_types_observed = set()  # 用于记录PCAP中出现过的协议类型 (TCP/UDP)

        dpkt_reader = self._read_dpkt_pcap()
        if dpkt_reader is None:
            return None

        self.datalink = dpkt_reader.datalink()
        packet_number = -1  # 初始化数据包编号

        try:
            for timestamp, raw_packet_data in dpkt_reader:
                packet_number += 1

                ip_packet = self._get_ip_packet(raw_packet_data)
                if not isinstance(ip_packet, dpkt.ip.IP):
                    warnings.warn(
                        f"包 {packet_number}: 非IP数据包，忽略。", category=UserWarning
                    )
                    continue

                transport_protocol_text: Union[str, None] = None
                transport_packet: Union[dpkt.tcp.TCP, dpkt.udp.UDP, None] = None

                if isinstance(ip_packet.data, dpkt.udp.UDP):
                    transport_protocol_text = "UDP"
                    transport_packet = ip_packet.data
                elif isinstance(ip_packet.data, dpkt.tcp.TCP):
                    transport_protocol_text = "TCP"
                    transport_packet = ip_packet.data
                else:
                    warnings.warn(
                        f"包 {packet_number}: 非TCP/UDP数据包，忽略。",
                        category=UserWarning,
                    )
                    continue

                protocol_types_observed.add(transport_protocol_text)  # 记录协议类型

                payload_size = self._get_payload_size(
                    ip_packet, transport_protocol_text
                )
                if payload_size is None:
                    warnings.warn(
                        f"包 {packet_number}: 无法获取负载大小，忽略。",
                        category=UserWarning,
                    )
                    continue

                # 记录第一个有效数据包的源IP，作为整个文件流的“正向”标志
                if not first_src_ip:
                    first_src_ip = inet_to_str(ip_packet.src)

                # 根据当前数据包的源IP与第一个包的源IP判断方向
                if inet_to_str(ip_packet.src) == first_src_ip:
                    single_stream_data.append(
                        [timestamp, f"+{payload_size}", packet_number]
                    )  # 正向 (来自第一个包的源IP)
                else:
                    single_stream_data.append(
                        [timestamp, f"-{payload_size}", packet_number]
                    )  # 反向 (来自与第一个包源IP不同的IP)

        except dpkt.dpkt.NeedData:
            pass  # 捕获部分pcap文件读取异常，无需额外处理
        except Exception as e:
            warnings.warn(
                f"处理PCAP文件(不分流模式)时发生未知错误: {e}", category=UserWarning
            )
        finally:
            # 确保文件句柄在处理完毕或发生异常时关闭
            if hasattr(dpkt_reader, "f") and not dpkt_reader.f.closed:
                dpkt_reader.f.close()

        # 确定最终的协议类型字符串
        if len(protocol_types_observed) == 1:
            final_protocol_text = protocol_types_observed.pop()
        elif len(protocol_types_observed) > 1:
            final_protocol_text = "mix"  # 混合协议类型
        else:
            final_protocol_text = ""  # 没有发现有效的TCP/UDP数据包

        return final_protocol_text, single_stream_data

    def _save_to_json(
        self, flow_streams: Dict[str, Any], output_dir: str, min_packet_num: int
    ) -> Tuple[int, str]:
        """
        将分流结果保存为JSON文件。每个流对应JSON数组中的一个对象。

        Args:
            flow_streams: 分流后的字典，键为五元组，值为流数据。
            output_dir: JSON文件的输出目录。
            min_packet_num: 过滤条件，只保存数据包数量大于此值的流。

        Returns:
            一个元组 (有效流数量, 输出文件路径)。
        """
        # 准备要写入JSON的数据结构
        json_output_list: List[Dict[str, Any]] = []

        for stream_key, stream_info in flow_streams.items():
            # 过滤掉数据包数量少于min_packet_num的流
            if len(stream_info["packets"]) <= min_packet_num:
                continue

            timestamps = [item[0] for item in stream_info["packets"]]
            payload_lengths_with_direction = [
                item[1] for item in stream_info["packets"]
            ]  # 例如: "+100", "-50"

            # 从五元组字符串中解析出IP、端口和协议信息
            # 格式为 "src_ip_src_port_dst_ip_dst_port_protocol"
            parts = stream_key.split("_")
            if len(parts) == 5:
                src_ip, src_port, dst_ip, dst_port, protocol = parts
            else:
                warnings.warn(
                    f"五元组键 '{stream_key}' 格式不正确，跳过此流。",
                    category=UserWarning,
                )
                continue

            stream_dict = {
                "timestamp": timestamps,
                "payload": payload_lengths_with_direction,
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "protocol": protocol,
            }
            if stream_info["sni"]:  # 如果有SNI，则加入到JSON数据中
                stream_dict["sni"] = stream_info["sni"]

            json_output_list.append(stream_dict)

        # 构建输出文件路径
        # 确保文件名中不包含 .pcap 扩展名，防止双重扩展
        base_filename = os.path.basename(self.input_pcap_file)
        if base_filename.lower().endswith(".pcap"):
            base_filename = base_filename[:-5]  # 移除 .pcap

        output_filename = f"{base_filename}.json"
        output_path = os.path.join(output_dir, output_filename)

        # 将数据写入JSON文件
        with open(output_path, "w", encoding="utf-8") as json_file:
            # 使用 separators=(",", ":") 减少JSON文件大小，indent=2 增加可读性
            # ensure_ascii=False 允许直接写入非ASCII字符，例如中文
            json.dump(
                json_output_list,
                json_file,
                separators=(",", ":"),
                indent=2,
                ensure_ascii=False,
            )

        return len(json_output_list), output_path

    def _save_to_pcap(
        self, flow_streams: Dict[str, Any], output_dir: str, min_packet_num: int
    ) -> Tuple[int, str]:
        """
        将分流结果保存为多个PCAP文件，每个流对应一个单独的PCAP文件。
        此方法利用预加载的Scapy数据包，高效地写入新文件。

        Args:
            flow_streams: 分流后的字典，键为五元组，值为流数据。
            output_dir: PCAP文件的输出目录。
            min_packet_num: 过滤条件，只保存数据包数量大于此值的流。

        Returns:
            一个元组 (有效流数量, 输出目录路径)。
        """
        if not self._scapy_packets:
            warnings.warn(
                "没有加载到Scapy数据包，无法保存PCAP文件。请检查输入PCAP文件是否有效。",
                category=UserWarning,
            )
            return 0, output_dir

        saved_sessions_count = 0
        # 获取原始PCAP文件名的基础部分，用于新文件名
        original_pcap_base_name = os.path.basename(self.input_pcap_file)
        if original_pcap_base_name.lower().endswith(".pcap"):
            original_pcap_base_name = original_pcap_base_name[:-5]  # 移除 .pcap

        for stream_key, stream_info in flow_streams.items():
            if len(stream_info["packets"]) <= min_packet_num:
                continue

            # 构建当前流的PCAP文件名
            # 替换文件名中可能导致路径问题的字符 (如冒号、斜杠)
            sanitized_stream_key = (
                stream_key.replace(":", "_").replace("/", "_").replace(".", "_")
            )
            pcap_filename = f"{original_pcap_base_name}_{sanitized_stream_key}.pcap"
            output_path = os.path.join(output_dir, pcap_filename)

            # 收集属于当前流的所有Scapy数据包
            packets_for_current_stream = scapy.PacketList()
            for packet_info in stream_info["packets"]:
                packet_index = packet_info[2]  # 获取原始数据包的索引 (第三个元素)
                if 0 <= packet_index < len(self._scapy_packets):
                    packets_for_current_stream.append(self._scapy_packets[packet_index])
                else:
                    warnings.warn(
                        f"数据包索引 {packet_index} 超出Scapy加载的数据包范围 ({len(self._scapy_packets)}), 跳过此包。",
                        category=UserWarning,
                    )

            if packets_for_current_stream:
                try:
                    # 使用 Scapy.wrpcap 将数据包写入新的PCAP文件
                    # wrpcap 会根据数据包的链路层类型自动选择正确的pcap头
                    scapy.wrpcap(output_path, packets_for_current_stream)
                    saved_sessions_count += 1
                except Exception as e:
                    warnings.warn(
                        f"写入PCAP文件 '{output_path}' 失败: {e}", category=UserWarning
                    )

        return saved_sessions_count, output_dir

    def split_flow(
        self,
        output_dir: str,
        min_packet_num: int = 0,
        tcp_from_first_packet: bool = False,
        output_type: str = "pcap",
    ) -> Union[Tuple[int, str], None]:
        """
        分流主函数，负责根据配置解析PCAP文件并将流量数据分流。
        支持将分流结果输出为多个PCAP文件或一个JSON文件。

        Args:
            output_dir: 存储分流结果的输出目录。
            min_packet_num: 过滤条件，只保留数据包数量大于此值的流。默认值为0。
            tcp_from_first_packet: 如果为True，对于TCP流，只保留以SYN握手包开始的流。默认值为False。
            output_type: 输出文件的类型，可选 "pcap" 或 "json"。默认值为 "pcap"。

        Returns:
            一个元组 (有效流数量, 输出路径)。
            如果处理失败或未发现有效流，则返回None。
        Raises:
            OSError: 如果输出类型不合法。
        """
        if output_type not in ("pcap", "json"):
            raise OSError("输出类型错误！请选择 'pcap' 或 'json'。")

        # 处理PCAP文件，获取分流后的流量数据
        flow_streams = self._process_pcap_file(tcp_from_first_packet)
        if flow_streams is None:
            print("未从PCAP文件中解析到任何有效流量流。")
            return None

        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        session_len: int
        output_path: str

        # 根据指定的输出类型保存结果
        if output_type == "pcap":
            session_len, output_path = self._save_to_pcap(
                flow_streams, output_dir, min_packet_num
            )
        elif output_type == "json":
            session_len, output_path = self._save_to_json(
                flow_streams, output_dir, min_packet_num
            )

        if session_len > 0:
            print(f"成功处理并保存了 {session_len} 个流量流。")
            print(f"输出路径: {output_path}")
        else:
            print(
                f"未发现满足最小数据包数 ({min_packet_num}) 要求的有效流量流，未生成文件。"
            )

        return session_len, output_path


if __name__ == "__main__":
    # --- 示例用法：解析PCAP文件并进行分流和不分流处理 ---
    # 请确保提供一个实际存在的PCAP文件路径，例如将其放在与脚本同目录下
    test_pcap_file = "./http_20250722074421_141.164.58.43_jp_google.com.pcap"

    # 定义输出目录
    output_directory_split_pcap = "./output_split_pcap"
    output_directory_split_json = "./output_split_json"
    output_directory_nosplit = "./output_nosplit"

    print(f"--- 开始处理 PCAP 文件: {test_pcap_file} ---")

    # --- 1. 测试按流分流并保存为PCAP文件 ---
    print("\n--- 1. 测试按流分流并保存为PCAP文件 (TCP流要求SYN握手) ---")
    if os.path.exists(test_pcap_file):
        try:
            # 实例化PcapHandler对象
            handler_pcap_output = PcapHandler(test_pcap_file)
            # 调用分流函数，要求TCP流从SYN开始，最少1个包，输出为pcap
            num_flows_pcap, output_path_pcap = handler_pcap_output.split_flow(
                output_directory_split_pcap,
                min_packet_num=1,
                tcp_from_first_packet=True,
                output_type="pcap",
            )
        except Exception as e:
            print(f"按流分流并保存为PCAP失败: {e}")
    else:
        print(f"错误: 测试PCAP文件 '{test_pcap_file}' 不存在，跳过PCAP分流测试。")

    # --- 2. 测试按流分流并保存为JSON文件 ---
    print("\n--- 2. 测试按流分流并保存为JSON文件 (TCP流不要求SYN握手) ---")
    if os.path.exists(test_pcap_file):
        try:
            # 实例化PcapHandler对象
            handler_json_output = PcapHandler(test_pcap_file)
            # 调用分流函数，不要求TCP流从SYN开始，最少1个包，输出为json
            num_flows_json, output_path_json = handler_json_output.split_flow(
                output_directory_split_json,
                min_packet_num=1,
                tcp_from_first_packet=False,
                output_type="json",
            )
        except Exception as e:
            print(f"按流分流并保存为JSON失败: {e}")
    else:
        print(f"错误: 测试PCAP文件 '{test_pcap_file}' 不存在，跳过JSON分流测试。")

    # --- 3. 测试不分流的处理方式 (_process_pcap_file_nosplit) ---
    print("\n--- 3. 测试不分流的处理方式 (将所有数据包视为一个流) ---")
    if os.path.exists(test_pcap_file):
        try:
            # 实例化PcapHandler对象
            handler_nosplit = PcapHandler(test_pcap_file)
            # 调用内部方法进行不分流处理
            protocol_type_nosplit, stream_data_nosplit = (
                handler_nosplit._process_pcap_file_nosplit()
            )

            if stream_data_nosplit:
                # 构建输出文件路径
                base_filename_nosplit = os.path.basename(test_pcap_file)
                if base_filename_nosplit.lower().endswith(".pcap"):
                    base_filename_nosplit = base_filename_nosplit[:-5]
                output_nosplit_file = os.path.join(
                    output_directory_nosplit,
                    f"{base_filename_nosplit}_all_packets_payload_info.json",
                )

                os.makedirs(output_directory_nosplit, exist_ok=True)
                with open(output_nosplit_file, "w", encoding="utf-8") as f:
                    # 将不分流的结果保存为JSON，包含协议类型和所有数据包信息
                    json.dump(
                        {
                            "protocol_type": protocol_type_nosplit,
                            "packets": stream_data_nosplit,
                        },
                        f,
                        indent=2,
                        ensure_ascii=False,
                    )
                print(
                    f"不分流处理完成。协议类型: {protocol_type_nosplit}, 总包数: {len(stream_data_nosplit)}, 结果保存到: {output_nosplit_file}"
                )
            else:
                print("不分流处理未发现有效数据包。")
        except Exception as e:
            print(f"不分流处理失败: {e}")
    else:
        print(f"错误: 测试PCAP文件 '{test_pcap_file}' 不存在，跳过不分流测试。")

    print("\n--- 所有测试完成 ---")
