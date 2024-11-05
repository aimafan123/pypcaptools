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

    def _save_to_json(self, tcpstream, input_pcap_file, output_dir):
        tcpstreams = []
        for stream in tcpstream:
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
        return True

    def _save_to_pcap(self, tcpstream, input_pcap_file, output_dir):
        packets = scapy.rdpcap(input_pcap_file)
        for stream in tcpstream:
            pcap_name = f"{os.path.basename(input_pcap_file)}_{stream}.pcap"
            output_path = os.path.join(output_dir, pcap_name)
            scapy.wrpcap(output_path, [])
            for packet in tcpstream[stream]:
                scapy.wrpcap(output_path, [packets[packet[2]]], append=True)
        return True

    def split_flow(
        self,
        output_dir,
        tcp_from_first_packet=False,
        output_type="pcap",
    ):
        if output_type not in ("pcap", "json"):
            raise OSError("output type is error! please select pcap or json")
        tcpstream = self._process_pcap_file(self.input_pcap_file, tcp_from_first_packet)
        os.makedirs(output_dir, exist_ok=True)
        return (
            self._save_to_pcap(tcpstream, self.input_pcap_file, output_dir)
            if output_type == "pcap"
            else self._save_to_json(tcpstream, self.input_pcap_file, output_dir)
        )
