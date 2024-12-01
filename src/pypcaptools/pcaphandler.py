# -*- coding: utf-8 -*-
import json
import os
import warnings

import dpkt
import scapy.all as scapy
from dpkt.utils import inet_to_str
import csv 

warnings.filterwarnings("ignore", message="No IPv4 address found")
class PcapHandler:
    def __init__(self, input_pcap_file):
        self.datalink = 1
        self.input_pcap_file = input_pcap_file

    def _getIP(self, pkt):
        if self.datalink == 1 or self.datalink == 239:
            return dpkt.ethernet.Ethernet(pkt).data # dpkt.ethernet表示dpkt库中的Ethernet，Ethernet表示Ethernet模块的构造函数
        elif self.datalink in (228, 229, 101):
            return dpkt.ip.IP(pkt) 
        else:
            raise TypeError("Unrecognized link-layer protocol!!!!")

    def _get_payload_size(self, ip, pro_type): 
        ip_header_length = ip.hl * 4 #IP头部的长度是以32位字为单位描述，每个 32 位字（即 4 字节）表示一个数据单元，所以ip.hl表示的是以32位字为单位的数量，那么我们要表示为字节的数量就要*4；
        ip_total_length = ip.len # 总长度是以字节为单位的
        if pro_type == "TCP":
            transport_header_length = ip.data.off * 4  # off 代表偏移量（offset），表示从TCP头部开始到TCP数据开始的字节数，单位为 4 字节，所以表示字节数量要表示为 *4；
        elif pro_type == "UDP":
            transport_header_length = 8
        else:
            return None
        payload_length = ip_total_length - ip_header_length - transport_header_length # payload长度
        return max(payload_length, 0)  # 确保返回非负值
    def _process_bursts(self, tcpstream, direction):
        pass

    def _process_pcap_file(self, file_name, first_packet_is_tcp): # first_packet_is_tcp是设置的一个bool变量，TRUE表示只收集TCP流量
        tcpstream = {}
        last_burst_end_time = None  # 用来记录上一个burst的结束时间
        """
        tcpstream结构：
            {
                "stream1":[[在原pcap文件中的序号], [包时间戳序列], [时间间隔序列], [包长序列], [包方向序列],  [stream中包的数量], [burst包数量序列], [burst进包数量序列], [burst出包数量序列], [burst大小序列], [burst进大小序列], [burst出大小序列], [burst时间间隔序列], [burst进时间间隔序列], [burst出时间间隔序列]],
                "stream2":[[...], [...], ...],
            }
        features:
            ("packet_serial_number_in_origin_pcap", 0),  # 时间戳序列
            ("timestamp", 1),  # 时间戳序列
            ("time_interval", 2),  # 时间间隔序列
            ("payload_length", 3),  # 包长序列
            ("direction", 4),  # 包方向序列
            ("stream_packet_count", 5),  # 流中包的数量
            ("burst_packet_count", 6),  # burst包数量序列
            ("burst_in_packet_count", 7),  # burst进包数量序列
            ("burst_out_packet_count", 8),  # burst出包数量序列
            ("burst_size", 9),  # burst大小序列
            ("burst_in_size", 10),  # burst进大小序列
            ("burst_out_size", 11),  # burst出大小序列
            ("burst_time_interval", 12),  # burst时间间隔序列
            ("burst_in_time_interval", 13),  # burst进时间间隔序列
            ("burst_out_time_interval", 14),  # burst出时间间隔序列
        """
        with open(file_name, "rb") as f:
            try:
                pkts = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                pkts = dpkt.pcapng.Reader(f) # 如果不是pcap格式的文件，看看是不是pcapng格式的
            except Exception as e:
                raise TypeError(f"Unable to open the pcap file: {e}")

            self.datalink = pkts.datalink() # 一般情况下一个pcap文件里面使用的都是同一种链路层协议
            number = -1 # 标记当前packet包在原始pcap文件中的序号
            try:
                for time, pkt in pkts:
                    number += 1
                    ip = self._getIP(pkt)
                    if not isinstance(ip, dpkt.ip.IP):
                        warnings.warn(
                            "this packet is not ip packet, ignore.", category=Warning
                        )
                        continue
                    pro_type = (
                        "TCP"
                        if isinstance(ip.data, dpkt.tcp.TCP)
                        # else "UDP"
                        # if isinstance(ip.data, dpkt.udp.UDP)
                        else None
                    )
                    if not pro_type:
                        continue
                    up_pro_pkt = ip.data # 上层协议数据包，也就是TCP/UDP等协议数据包
                    payload_length = self._get_payload_size(ip, pro_type)
                    srcport, dstport, srcip, dstip = (
                        up_pro_pkt.sport, # 读取出来自动换成十进制
                        up_pro_pkt.dport,
                        inet_to_str(ip.src),  # ip原本是二进制形式
                        inet_to_str(ip.dst),
                    )
                    siyuanzu1 = f"{srcip}_{srcport}_{dstip}_{dstport}_{pro_type}" #出五元组
                    siyuanzu2 = f"{dstip}_{dstport}_{srcip}_{srcport}_{pro_type}" #进五元组

                    if siyuanzu1 in tcpstream:
                        stream_key = siyuanzu1
                        direction = "+"
                        # tcpstream[siyuanzu1][0].append(time) 
                        # tcpstream[siyuanzu1][1].append(f"+{payload_length}")  # 字符串中的正负表示数据包的方向
                        # tcpstream[siyuanzu1][2].append(number)
                        # tcpstream[siyuanzu1][3] += 1  # 更新序列长度
                    elif siyuanzu2 in tcpstream:
                        stream_key = siyuanzu2
                        direction = "-"
                        # tcpstream[siyuanzu2][0].append(time) 
                        # tcpstream[siyuanzu2][1].append(f"+{payload_length}")  # 字符串中的正负表示数据包的方向
                        # tcpstream[siyuanzu2][2].append(number)
                        # tcpstream[siyuanzu2][3] += 1  # 更新序列长度
                    else:
                        if pro_type == "TCP" and first_packet_is_tcp: 
                            first_flag = self._getIP(pkt).data.flags # tcp.flags字段等于2代表是第一个TCP握手包
                            if first_flag != 2:
                                continue
                        stream_key = siyuanzu1
                        tcpstream[stream_key] = [[], [], [], [], [], [0,], [], [], [], [], [], [], [], [], []] # 新键值对加入字典
                        direction = "+"

                    # 更新流的信息
                    # 更新流信息
                    stream_data = tcpstream[stream_key]
                    stream_data[0].append(number)  # 在原pcap文件中的序号
                    stream_data[1].append(time)  # 包时间戳序列
                    stream_data[3].append(payload_length)  # 包长序列
                    stream_data[4].append(1 if direction == "+" else -1)  # 包方向序列
                    stream_data[5][0] += 1  # 更新stream中的包数量
                    stream_data[5].append([])
                    # 更新时间间隔序列
                    if len(stream_data[1]) > 1:
                        time_interval = time - stream_data[1][-2]
                        stream_data[2].append(time_interval)
                    else:
                        stream_data[2].append(0)

                    # 更新 burst 逻辑
                    # 根据方向（进/出）和时间间隔统计 burst 信息
                    current_burst = {
                        "size": payload_length,
                        "count": 1,
                        "timestamps": [time], #每个数据包到达时更新为每个数据包的时间戳
                    }

                    # 如果上一个 burst 的结束时间存在，则计算时间间隔
                    if last_burst_end_time is not None:
                        burst_time_interval = time - last_burst_end_time
                        if direction == "+":
                            stream_data[13].append(burst_time_interval)
                        elif direction == "-":
                            stream_data[14].append(burst_time_interval)

                    # 更新上一个 burst 的结束时间
                    last_burst_end_time = time
                    stream_data[6].append(current_burst["count"]) # 更新burst长度序列
                    if direction == "+":
                        # 更新进方向的 burst 数据
                        stream_data[7].append(current_burst["count"])
                        stream_data[10].append(current_burst["size"])
                    else:
                        # 更新出方向的 burst 数据
                        stream_data[8].append(current_burst["count"])
                        stream_data[11].append(current_burst["size"])
                        # tcpstream[siyuanzu1][0].append(time) 
                        # tcpstream[siyuanzu1][1].append(f"+{payload_length}")  # 字符串中的正负表示数据包的方向
                        # tcpstream[siyuanzu1][2].append(number)
                        # tcpstream[siyuanzu1][3] = 1  # 初始化长度为 1
                        # tcpstream[siyuanzu1][4].append() # burst包数量序列
            except dpkt.dpkt.NeedData:
                pass  # 什么都不做，主要用于占位，避免语法错误。
        return tcpstream # 返回一个pcap文件的所有流序列
    
    # def _get_flow_packets_number(self, tcpstream):


    def _save_to_json(self, tcpstream, input_pcap_file, output_dir):
        tcpstreams = [] # 因为json格式就是一个一维列表，每个元素是一个字典
        for stream_name, stream_data in tcpstream: # 遍历每一条流
            # time_stamps = [item[0] for item in tcpstream[stream]]# 提取时间戳序列
            # lengths = [item[1] for item in tcpstream[stream]]# 提取包长序列
            # 将序列和五元组解析成适应json文件的格式，也就是每个流有一个字典，这个字典里面有序列和五元组；
            dict_data = {
                "timestamp": stream_data[0],
                "payload_length": stream_data[1],
                "flow_pakcets_number": stream_data[2], # 流中数据包的数量
                **dict(
                    zip(
                        ["src_ip", "src_port", "dst_ip", "dst_port", "protocol"],
                        stream_name.split("_"),
                    )
                ),
            }
            tcpstreams.append(dict_data) # 将流字典加入json列表中；

        json_data = json.dumps(tcpstreams, separators=(",", ":"), indent=2) # 其中tcpstreams格式要与json格式相匹配，这样才能正确转换为json字符串
        output_path = os.path.join(
            output_dir, f"{os.path.basename(input_pcap_file)}.json"
        ) # 将使用 input_pcap_file 的文件名，并将其扩展名更改为 .json，然后将其与 output_dir 目录路径合并，形成一个完整的输出路径
        with open(output_path, "w") as json_file:
            json_file.write(json_data) # 将数据写入json文件
        return True

    def _save_to_pcap(self, tcpstream, input_pcap_file, output_dir): 
        packets = scapy.rdpcap(input_pcap_file) # 用scapy库读取pcap文件
        for stream_name, stream_data in tcpstream.items():
            pcap_name = f"{os.path.basename(input_pcap_file)}_{stream_name}.pcap" # 以每个流的五元组命名pcap文件
            output_path = os.path.join(output_dir, pcap_name)
            scapy.wrpcap(output_path, []) # 用空列表初始化一个pcap文件
            for packet in stream_data[2]:
                scapy.wrpcap(output_path, [packets[packet]], append=True) # 将数据包追加到pcap文件中
        return True
    def _save_to_csv(self, tcpstream, input_pcap_file, output_dir, feature_index = 3): # 默认提取的特征序列是“包长序列”
        # 定义每个特征对应的 CSV 文件名称
        features = [
            ("packet_serial_number_in_origin_pcap", 0),  # 时间戳序列
            ("timestamp", 1),  # 时间戳序列
            ("time_interval", 2),  # 时间间隔序列
            ("payload_length", 3),  # 包长序列
            ("direction", 4),  # 包方向序列
            ("stream_packet_count", 5),  # 流中包的数量
            ("burst_packet_count", 6),  # burst包数量序列
            ("burst_in_packet_count", 7),  # burst进包数量序列
            ("burst_out_packet_count", 8),  # burst出包数量序列
            ("burst_size", 9),  # burst大小序列
            ("burst_in_size", 10),  # burst进大小序列
            ("burst_out_size", 11),  # burst出大小序列
            ("burst_time_interval", 12),  # burst时间间隔序列
            ("burst_in_time_interval", 13),  # burst进时间间隔序列
            ("burst_out_time_interval", 14),  # burst出时间间隔序列
        ]
        feature_name = features[feature_index][0]
        output_path = os.path.join(output_dir, f"{os.path.basename(input_pcap_file)}_{feature_name}.csv")
        with open(output_path, mode='w', newline='') as csvfile: # 准备写入 CSV 文件
            csv_writer = csv.writer(csvfile)
            for stream_name, stream_data in tcpstream.items(): # 遍历每个流（流的名称为键，值是包含数据的列表）
                feature_data = stream_data[feature_index] # 获取该特征的序列
                row = [stream_name] # 写入第一列是流名
                row.extend(feature_data)
                csv_writer.writerow(row)
        return True  # 保存成功返回 True

    def split_flow(self, output_dir, first_packet_is_tcp=False, output_type="pcap"):
        if output_type not in ("pcap", "json", "csv"):
            raise OSError("output type is error! please select pcap or json")
        tcpstream = self._process_pcap_file(self.input_pcap_file, first_packet_is_tcp)
        os.makedirs(output_dir, exist_ok=True) # 如果目录output_dir不存在，则创建一个目录
        return (
            self._save_to_pcap(tcpstream, self.input_pcap_file, output_dir)
            if output_type == "pcap" else
            self._save_to_json(tcpstream, self.input_pcap_file, output_dir)
            if output_type == "json" else
            self._save_to_csv(tcpstream, self.input_pcap_file, output_dir)
        )
    
    # 统计流序列长度
    def feature_sequence_of_flow(self, output_dir, first_packet_is_tcp=False, output_type="csv", feature = 3): # 默认提取的特征也是包长序列
        if output_type not in ("csv"):
            raise OSError("output type is error! please select csv")
        tcpstream = self._process_pcap_file(self.input_pcap_file, first_packet_is_tcp)
        os.makedirs(output_dir, exist_ok=True) # 如果目录output_dir不存在，则创建一个目录
        feature_index = feature
        # with open(output_path, mode='w', newline='') as csvfile: # 准备写入 CSV 文件
        #     csv_writer = csv.writer(csvfile)
        #     for stream_name, stream_data in tcpstream.items(): # 遍历每个流（流的名称为键，值是包含数据的列表）
        #         row = [stream_name]  # 第一列是流的名称
        #         row.append(stream_data[3])  # 第一个列表中的第i个元素
        #         csv_writer.writerow(row)
        return self._save_to_csv(tcpstream, self.input_pcap_file, output_dir, feature_index)

    # todo 
    # 统计burst包数量序列，也就是每个burst包含多少个数据包，主要目的为了观察每个burst数据包数量的分布；
    # 
    # 统计burst大小序列；
    # 统计输出burst大小序列；
    # 统计输入burst大小序列；
    # 统计时间间隔序列；
    # 进出时间间隔序列；
    # 提取包方向序列（-1，-1，-1，1，1，1，）优先级比较低，等发现burst数据包数量的分布有什么可以做的再写也可以；