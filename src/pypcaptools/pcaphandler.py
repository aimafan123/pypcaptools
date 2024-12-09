# -*- coding: utf-8 -*-
import json
import os
import warnings

import dpkt
import scapy.all as scapy
from dpkt.utils import inet_to_str


class PcapHandler:
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

    def _process_pcap_file(self, file_name, tcp_from_first_packet):
        tcpstream = {}
        if os.path.getsize(file_name) <= 10:
            print("The pcap file is empty, skipping...")
            return None
        with open(file_name, "rb") as f:
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
                        tcpstream[siyuanzu1].append([time, f"+{payload}", number])
                    elif siyuanzu2 in tcpstream:
                        tcpstream[siyuanzu2].append([time, f"-{payload}", number])
                    else:
                        if pro_txt == "TCP" and tcp_from_first_packet:
                            first_flag = self._getIP(pkt).data.flags
                            if first_flag != 2:
                                continue
                        tcpstream[siyuanzu1] = [[time, f"+{payload}", number]]
            except dpkt.dpkt.NeedData:
                pass
        return tcpstream

    def _save_to_json(self, tcpstream, input_pcap_file, output_dir, min_packet_num):
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
            output_dir, f"{os.path.basename(input_pcap_file)}.json"
        )
        with open(output_path, "w") as json_file:
            json_file.write(json_data)
        return len(tcpstreams), output_path

    def _save_to_pcap(self, tcpstream, input_pcap_file, output_dir, min_packet_num):
        packets = scapy.rdpcap(input_pcap_file)
        session_len = 0
        for stream in tcpstream:
            if len(tcpstream[stream]) <= min_packet_num:
                continue
            pcap_name = f"{os.path.basename(input_pcap_file)}_{stream}.pcap"
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
        tcpstream = self._process_pcap_file(self.input_pcap_file, tcp_from_first_packet)
        if tcpstream is None:
            return
        os.makedirs(output_dir, exist_ok=True)
        if output_type == "pcap":
            session_len, output_path = self._save_to_pcap(
                tcpstream, self.input_pcap_file, output_dir, min_packet_num
            )
        elif output_type == "json":
            session_len, output_path = self._save_to_json(
                tcpstream, self.input_pcap_file, output_dir, min_packet_num
            )
        return session_len, output_path


if __name__ == "__main__":
    pcap_handler = PcapHandler("./test.pcap")
    aa = pcap_handler.split_flow("test_dir")
