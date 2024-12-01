import warnings
from pypcaptools import PcapHandler




if __name__ == "__main__":
    warnings.filterwarnings("ignore")  # 忽略所有警告

    # origin_pcap = "/path/dir/output_dir"
    origin_pcap = "/Users/slomay/Desktop/HM/中关村/academic/流量数据集/脚本/流量数据分割/pypcaptools/pcap/google_20240511.pcap"

    ph = PcapHandler(origin_pcap)
    # output_dir = "/path/dir/output_dir"
    output_dir = "/Users/slomay/Desktop/HM/中关村/academic/流量数据集/脚本/流量数据分割/pypcaptools/csv"

    # 分流之后以pcap格式输出，TCP流允许从中途开始（即没有握手过程）
    # ph.split_flow(output_dir, tcp_from_first_packet=False, output_type="pcap")

    # 分流之后以json格式输出，输出一个json文件，其中每一个单元表示一条流，TCP流必须从握手阶段开始，从中途开始的TCP流会被丢弃
    # ph.split_flow(output_dir, first_packet_is_tcp=True, output_type="csv") # 只解析TCP流量

    # 提取pcap文件中每个流序列长度
    ph.feature_sequence_of_flow(output_dir, first_packet_is_tcp=True, output_type="csv", feature = 0)

    print("Processing completed.")

"""提取特征函数
1.分流函数：
    # 分流之后以pcap格式输出，TCP流允许从中途开始（即没有握手过程）
    # ph.split_flow(output_dir, tcp_from_first_packet=False, output_type="pcap")

    # 分流之后以json格式输出，输出一个json文件，其中每一个单元表示一条流，TCP流必须从握手阶段开始，从中途开始的TCP流会被丢弃
    # ph.split_flow(output_dir, first_packet_is_tcp=True, output_type="csv") # 只解析TCP流量

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
2.提取包长序列函数：(以下函数都只是写了csv存储形式)
    # 关于first_packet_is_tcp变量的使用和上面是一样的
    ph.feature_sequence_of_flow(output_dir, first_packet_is_tcp=True, output_type="csv", feature = 3)

"""