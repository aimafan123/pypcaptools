# -*- coding: utf-8 -*-
import json
import os
import warnings

import dpkt
import scapy.all as scapy
from dpkt.utils import inet_to_str

class PcapHandler:
    # # TLS版本号映射
    tls_versions = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

    def __init__(self, input_pcap_file):
        self.datalink = 1
        self.input_pcap_file = input_pcap_file

    def _getIP(self, pkt):
        if self.datalink == 1 or self.datalink == 239:
            return dpkt.ethernet.Ethernet(pkt).data
        elif self.datalink in (228, 229, 101):
            return dpkt.ip.IP(pkt)
        elif self.datalink == 276:  # linux cooked capture v2
            return dpkt.sll2.SLL2(pkt).data
        else:
            raise TypeError("Unrecognized link-layer protocol!!!!")

    def _get_payload_size(self, ip, pro_txt):
        ip_header_length = ip.hl * 4
        ip_total_length = ip.len
        if pro_txt == "TCP":
            transport_header_length = ip.data.off * 4
        elif pro_txt == "UDP":
            transport_header_length = 8
        else:
            return None
        return ip_total_length - ip_header_length - transport_header_length

    def _raw_extract_sni(self, data):
        """直接从二进制数据中提取SNI，而不依赖dpkt的解析"""
        try:
            # 寻找Client Hello消息
            # 格式: TLS Record (0x16) + 版本 + 长度 + Handshake类型(0x01) + ...

            offset = 0
            while offset < len(data) - 10:
                # 检查是否是握手记录
                if data[offset] == 0x16:  # 0x16 = handshake
                    # 检查是否是Client Hello
                    handshake_type_offset = offset + 5  # TLS记录头部后的位置
                    if len(data) > handshake_type_offset and data[handshake_type_offset] == 0x01:  # 0x01 = Client Hello
                        # 解析Client Hello
                        # 跳过TLS记录头(5字节)和Handshake头(4字节)
                        client_hello_offset = offset + 9

                        # 检查是否有足够的数据
                        if len(data) < client_hello_offset + 34:  # Client Hello头部最小长度
                            offset += 1
                            continue

                        # 跳过Client Hello固定部分(版本2字节 + 随机32字节)
                        session_id_len_offset = client_hello_offset + 34
                        if len(data) <= session_id_len_offset:
                            offset += 1
                            continue

                        # 获取会话ID长度并跳过
                        session_id_len = data[session_id_len_offset]
                        cipher_suites_len_offset = session_id_len_offset + 1 + session_id_len
                        if len(data) <= cipher_suites_len_offset + 1:
                            offset += 1
                            continue

                        # 获取加密套件长度并跳过
                        cipher_suites_len = (data[cipher_suites_len_offset] << 8) | data[cipher_suites_len_offset + 1]
                        comp_methods_len_offset = cipher_suites_len_offset + 2 + cipher_suites_len
                        if len(data) <= comp_methods_len_offset:
                            offset += 1
                            continue

                        # 获取压缩方法长度并跳过
                        comp_methods_len = data[comp_methods_len_offset]
                        extensions_len_offset = comp_methods_len_offset + 1 + comp_methods_len
                        if len(data) <= extensions_len_offset + 1:
                            offset += 1
                            continue

                        # 获取扩展总长度
                        extensions_len = (data[extensions_len_offset] << 8) | data[extensions_len_offset + 1]
                        extension_offset = extensions_len_offset + 2
                        extensions_end = extension_offset + extensions_len

                        # 解析每个扩展
                        while extension_offset < extensions_end - 3:
                            # 获取扩展类型
                            ext_type = (data[extension_offset] << 8) | data[extension_offset + 1]
                            ext_len = (data[extension_offset + 2] << 8) | data[extension_offset + 3]
                            ext_data_offset = extension_offset + 4

                            # 检查是否是Server Name扩展(0)
                            if ext_type == 0 and ext_len > 2:
                                # 解析Server Name列表
                                sni_list_len = (data[ext_data_offset] << 8) | data[ext_data_offset + 1]
                                sni_offset = ext_data_offset + 2

                                # 确保我们有足够的数据
                                if sni_offset + 1 < len(data) and data[sni_offset] == 0:  # 类型 0 = hostname
                                    name_len = (data[sni_offset + 1] << 8) | data[sni_offset + 2]
                                    name_offset = sni_offset + 3

                                    # 提取主机名
                                    if name_offset + name_len <= len(data):
                                        try:
                                            hostname = data[name_offset:name_offset + name_len].decode('utf-8',
                                                                                                       errors='replace')
                                            return hostname
                                        except:
                                            pass

                            # 移动到下一个扩展
                            extension_offset += 4 + ext_len

                # 移动到下一个可能的记录
                offset += 1

            return None
        except Exception as e:
            return None

    def _process_tcp_packet(self, tcpstream, undeal_segments, number, pro, siyuanzu1, siyuanzu2, dstport, srcport):
        temp_tcpstream = tcpstream.copy()
        temp_undeal_segments = undeal_segments.copy()
        if dstport == 443 or srcport == 443:
            encryption_method = 'TLS'
        else:
            return temp_tcpstream, temp_undeal_segments
        all_tcp_data = pro.data
        finish_segment = None

        if len(all_tcp_data) > 5:
            seq_num = pro.seq
            ack_num = pro.ack
            # 判断是否需要拼接数据
            if len(temp_undeal_segments) > 0:
                for undeal_segment in temp_undeal_segments:
                    if siyuanzu1 == undeal_segment["conversation_key"] and seq_num == undeal_segment[
                        "next_seg_seq"] and ack_num == undeal_segment["ack_num"]:
                        all_tcp_data = undeal_segment["data"] + pro.data
                        finish_segment = undeal_segment
                        break
                    elif siyuanzu2 == undeal_segment["conversation_key"] and seq_num == undeal_segment[
                        "next_seg_seq"] and ack_num == undeal_segment["ack_num"]:
                        all_tcp_data = undeal_segment["data"] + pro.data
                        finish_segment = undeal_segment
                        break

            handshake_type = all_tcp_data[5]
            # 握手类型: 1 = Client Hello, 2 = Server Hello
            if (pro.data[0] == 22 and handshake_type == 1) or finish_segment:
                is_continue = False
                if siyuanzu1 in temp_tcpstream and temp_tcpstream[siyuanzu1]['sni'] == '':
                    is_continue = True
                elif siyuanzu2 in temp_tcpstream and temp_tcpstream[siyuanzu2]['sni'] == '':
                    is_continue = True
                if is_continue:
                    # 处理Client Hello，获取SNI
                    sni = self._raw_extract_sni(all_tcp_data)

                    if finish_segment:
                        temp_undeal_segments.remove(finish_segment)
                    if sni is None:
                        temp_undeal_segments.append({"conversation_key": siyuanzu1, "data": all_tcp_data,
                                                "next_seg_seq": seq_num + len(pro.data), "ack_num": ack_num,
                                                'total_packets': number})
                    else:
                        if siyuanzu1 in temp_tcpstream:
                            temp_tcpstream[siyuanzu1]['sni'] = sni
                            temp_tcpstream[siyuanzu1]['encryption_method'] = encryption_method
                        elif siyuanzu2 in temp_tcpstream:
                            temp_tcpstream[siyuanzu2]['sni'] = sni
                            temp_tcpstream[siyuanzu2]['encryption_method'] = encryption_method
            elif pro.data[0] == 22 and handshake_type == 2:
                is_continue = False
                if siyuanzu1 in temp_tcpstream and temp_tcpstream[siyuanzu1]['cipher_suite'] == '':
                    is_continue = True
                elif siyuanzu2 in temp_tcpstream and temp_tcpstream[siyuanzu2]['cipher_suite'] == '':
                    is_continue = True
                if is_continue:
                    handshake_data = all_tcp_data[5:]
                    # print(f"{total_packets}, Sever Hello")
                    # 握手层从TCP数据的第5个字节开始
                    actual_version_bytes = handshake_data[4:6]
                    handshake_version = (actual_version_bytes[0] << 8) | actual_version_bytes[1]
                    tls_version = self.tls_versions.get(handshake_version, f"Unknown (0x{handshake_version:04x})")
                    # 跳过版本字段(2字节)、随机数(32字节)
                    offset = 6 + 32

                    # 跳过Session ID Length
                    if offset < len(handshake_data):
                        session_id_length = handshake_data[offset]
                        offset += 1 + session_id_length

                    # 跳过cipher suite (2字节) 之后处理,加密套件
                    if offset + 2 <= len(handshake_data):
                        cipher_suite_bytes = handshake_data[offset + 0: offset + 2]
                        # print('cipher_suite_bytes', cipher_suite_bytes.hex().upper())
                        if siyuanzu1 in temp_tcpstream:
                            temp_tcpstream[siyuanzu1]['cipher_suite'] = cipher_suite_bytes.hex().upper()
                        elif siyuanzu2 in temp_tcpstream:
                            temp_tcpstream[siyuanzu2]['cipher_suite'] = cipher_suite_bytes.hex().upper()
                        offset += 2

                    # 跳过Compression Method (1字节)
                    if offset + 1 <= len(handshake_data):
                        offset += 1

                    # 检查是否有扩展
                    if offset + 2 <= len(handshake_data):
                        extensions_length_bytes = handshake_data[offset + 0: offset + 2]
                        extensions_length = (extensions_length_bytes[0] << 8) | extensions_length_bytes[1]
                        offset += 2
                        supported_versions_extension_bytes = handshake_data[offset + 0: offset + 2]
                        supported_versions_extension = (supported_versions_extension_bytes[0] << 8) | \
                                                       supported_versions_extension_bytes[1]

                        supported_version_bytes = handshake_data[offset + 4: offset + 6]
                        supported_version = (supported_version_bytes[0] << 8) | supported_version_bytes[1]
                        if extensions_length == 46 and supported_versions_extension == 43:
                            tls_version = self.tls_versions.get(supported_version,
                                                                f"Unknown (0x{handshake_version:04x})")

                    if siyuanzu1 in temp_tcpstream:
                        temp_tcpstream[siyuanzu1]['tls_version'] = tls_version
                    elif siyuanzu2 in temp_tcpstream:
                        temp_tcpstream[siyuanzu2]['tls_version'] = tls_version

        return temp_tcpstream, temp_undeal_segments

    def _process_pcap_file(self, tcp_from_first_packet):
        tcpstream = {}
        undeal_segments = []
        if os.path.getsize(self.input_pcap_file) <= 10:
            print("The pcap file is empty, skipping...")
            return None
        with open(self.input_pcap_file, "rb") as f:
            try:
                pkts = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                pkts = dpkt.pcapng.Reader(f)
            except Exception as e:
                raise TypeError(f"Unable to open the pcap file: {e}")

            self.datalink = pkts.datalink()
            number = -1
            try:
                for time, pkt in pkts:
                    number += 1
                    ip = self._getIP(pkt)
                    if not isinstance(ip, dpkt.ip.IP):
                        warnings.warn(
                            "this packet is not ip packet, ignore.", category=Warning
                        )
                        continue
                    pro_txt = (
                        "UDP"
                        if isinstance(ip.data, dpkt.udp.UDP)
                        else "TCP"
                        if isinstance(ip.data, dpkt.tcp.TCP)
                        else None
                    )
                    if not pro_txt:
                        continue
                    pro = ip.data
                    payload = self._get_payload_size(ip, pro_txt)
                    srcport, dstport, srcip, dstip = (
                        pro.sport,
                        pro.dport,
                        inet_to_str(ip.src),
                        inet_to_str(ip.dst),
                    )
                    siyuanzu1 = f"{srcip}_{srcport}_{dstip}_{dstport}_{pro_txt}"
                    siyuanzu2 = f"{dstip}_{dstport}_{srcip}_{srcport}_{pro_txt}"

                    if siyuanzu1 in tcpstream:
                        tcpstream[siyuanzu1]['payload_list'].append([time, f"+{payload}", number])
                    elif siyuanzu2 in tcpstream:
                        tcpstream[siyuanzu2]['payload_list'].append([time, f"-{payload}", number])
                    else:
                        if pro_txt == "TCP" and tcp_from_first_packet:
                            first_flag = self._getIP(pkt).data.flags
                            if first_flag != 2:
                                continue
                        tcpstream[siyuanzu1] =  {'sni': '', 'tls_version': '', 'cipher_suite': '', 'encryption_method': '', 'payload_list' : [[time, f"+{payload}", number]]}
                    # 处理TCP
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcpstream, undeal_segments = self._process_tcp_packet(tcpstream, undeal_segments, number, pro, siyuanzu1, siyuanzu2, dstport, srcport)
                    # 处理UDP
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        is_continue = False
                        if siyuanzu1 in tcpstream and tcpstream[siyuanzu1]['encryption_method'] == '':
                            is_continue = True
                        elif siyuanzu2 in tcpstream and tcpstream[siyuanzu2]['encryption_method'] == '':
                            is_continue = True
                        if is_continue:
                            if dstport == 443 or srcport == 443:
                                encryption_method = 'QUIC'
                                if siyuanzu1 in tcpstream:
                                    tcpstream[siyuanzu1]['encryption_method'] = encryption_method
                                elif siyuanzu2 in tcpstream:
                                    tcpstream[siyuanzu2]['encryption_method'] = encryption_method

            except dpkt.dpkt.NeedData:
                pass
        return tcpstream

    def _process_pcap_file_nosplit(self):
        tcpstream = []
        first_src_ip = ""
        if os.path.getsize(self.input_pcap_file) <= 10:
            print("The pcap file is empty, skipping...")
            return None
        with open(self.input_pcap_file, "rb") as f:
            try:
                pkts = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                pkts = dpkt.pcapng.Reader(f)
            except Exception as e:
                raise TypeError(f"Unable to open the pcap file: {e}")

            self.datalink = pkts.datalink()
            number = -1
            try:
                for time, pkt in pkts:
                    number += 1
                    ip = self._getIP(pkt)
                    if not isinstance(ip, dpkt.ip.IP):
                        warnings.warn(
                            "this packet is not ip packet, ignore.", category=Warning
                        )
                        continue
                    pro_txt = (
                        "UDP"
                        if isinstance(ip.data, dpkt.udp.UDP)
                        else "TCP"
                        if isinstance(ip.data, dpkt.tcp.TCP)
                        else None
                    )
                    if not pro_txt:
                        continue
                    payload = self._get_payload_size(ip, pro_txt)
                    if not first_src_ip:
                        first_src_ip = inet_to_str(ip.src)
                    if inet_to_str(ip.src) == first_src_ip:
                        tcpstream.append([time, f"+{payload}", number])
                    else:
                        tcpstream.append([time, f"-{payload}", number])
            except dpkt.dpkt.NeedData:
                pass
        return pro_txt, tcpstream

    def _save_to_json(self, tcpstream, output_dir, min_packet_num):
        tcpstreams = []
        for stream in tcpstream:
            if len(tcpstream[stream]) <= min_packet_num:
                continue
            time_stamps = [item[0] for item in tcpstream[stream]]
            lengths = [item[1] for item in tcpstream[stream]]
            dict_data = {
                "timestamp": time_stamps,
                "payload": lengths,
                **dict(
                    zip(
                        ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
                        stream.split("_"),
                    )
                ),
            }
            tcpstreams.append(dict_data)

        json_data = json.dumps(tcpstreams, separators=(",", ":"), indent=2)
        output_path = os.path.join(
            output_dir, f"{os.path.basename(self.input_pcap_file)}.json"
        )
        with open(output_path, "w") as json_file:
            json_file.write(json_data)
        return len(tcpstreams), output_path

    def _save_to_pcap(self, tcpstream, output_dir, min_packet_num):
        packets = scapy.rdpcap(self.input_pcap_file)
        session_len = 0
        for stream in tcpstream:
            if len(tcpstream[stream]) <= min_packet_num:
                continue
            pcap_name = f"{os.path.basename(self.input_pcap_file)}_{stream}.pcap"
            output_path = os.path.join(output_dir, pcap_name)
            # 使用 PcapWriter 来创建输出文件，保持输入文件的封装类型
            with scapy.PcapWriter(output_path, append=False, sync=True) as pcap_writer:
                # 写入流中满足条件的数据包
                for packet in tcpstream[stream]:
                    pcap_writer.write(packets[packet[2]])
            session_len += 1
        return session_len, output_dir

    def split_flow(
        self,
        output_dir,
        min_packet_num=0,
        tcp_from_first_packet=False,
        output_type="pcap",
    ):
        # TODO: 加入并行
        """
        output_dir: 分流之后存储的路径
        min_pcaket_num: 流中最少有多少个数据包, 默认为0
        tcp_from_first_packet: 分流之后的流，是否一定有握手包，默认不一定
        output_type: 输出的格式，包括pcap和json，如果输出json的话，那么只有一个json文件
        """
        if output_type not in ("pcap", "json"):
            raise OSError("output type is error! please select pcap or json")
        tcpstream = self._process_pcap_file(tcp_from_first_packet)
        if tcpstream is None:
            return
        os.makedirs(output_dir, exist_ok=True)
        if output_type == "pcap":
            session_len, output_path = self._save_to_pcap(
                tcpstream, output_dir, min_packet_num
            )
        elif output_type == "json":
            session_len, output_path = self._save_to_json(
                tcpstream, output_dir, min_packet_num
            )
        return session_len, output_path


if __name__ == "__main__":
    # start = time.time()
    # print('start', start)
    # directory = r"E:\Study\Code\pypcaptools\data"
    # pcap_files = []
    # for root, dirs, files in os.walk(directory):
    #     for file in files:
    #         # 检查文件扩展名是否为.pcap（不区分大小写）
    #         if file.lower().endswith('.pcap'):
    #             full_path = os.path.join(root, file)
    #             pcap_files.append(full_path)
    # for pcap_file in pcap_files:
    #     pcap_handler = PcapHandler(pcap_file)
    #
    #     bb = pcap_handler._process_pcap_file(False)
    #
    # end = time.time()
    # print('end', end)
    # print('time', end - start)

    # pcap_handler = PcapHandler(
    #     r"E:\Study\Code\pypcaptools\data\data\atlanta_ubuntu24.04_novpn_20250226_145630_uniqlo.com.pcap")
    #
    # bb = pcap_handler._process_pcap_file(False)
    # print(bb)

    pcap_handler = PcapHandler(
        "./http_20241216214756_141.164.58.43_jp_bilibili.com.pcap"
    )

    bb, aa = pcap_handler._process_pcap_file_nosplit()
    print(bb)
