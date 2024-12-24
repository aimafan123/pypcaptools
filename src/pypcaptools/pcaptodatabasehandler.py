from datetime import datetime

from pypcaptools.pcaphandler import PcapHandler
from pypcaptools.TrafficDB.FlowDB import FlowDB
from pypcaptools.TrafficDB.TraceDB import TraceDB
from pypcaptools.util import DBConfig, serialization


class PcapToDatabaseHandler(PcapHandler):
    def __init__(
        self,
        db_config: DBConfig,
        input_pcap_file,
        protocol,
        accessed_website,
        collection_machine="",
        comment="",
    ):
        # db_config = {"host": ,"port": ,"user": ,"password": , "database": ,"table": }
        # input_pcap_file：处理的pcap路径
        # protocol：协议类型（应用层协议）
        # accessed_website：访问的网站/应用
        # collection_machine：用于收集的机器
        super().__init__(input_pcap_file)
        self.db_config = db_config
        self.protocol = protocol
        self.accessed_website = accessed_website
        self.collection_machine = collection_machine
        self.pcap_path = input_pcap_file
        self.comment = comment

    def _save_to_database(self, tcpstream, min_packet_num, trace_id=-1, first_time=0):
        if trace_id == 0:
            return
        host = self.db_config["host"]
        user = self.db_config["user"]
        port = self.db_config["port"]
        password = self.db_config["password"]
        database = self.db_config["database"]
        table = self.db_config["table"]

        if trace_id == -1:
            traffic = FlowDB(host, port, user, password, database, table)
            traffic.connect()
        else:
            traffic = TraceDB(host, port, user, password, database, table)
            traffic.connect()

        for stream in tcpstream:
            if len(tcpstream[stream]) <= min_packet_num:
                continue
            traffic_dic = {}
            if trace_id != -1:
                traffic_dic["trace_id"] = trace_id
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            traffic_dic["entry_time"] = now
            if first_time == 0:
                first_time = tcpstream[stream][0][0]
            traffic_dic["capture_time"] = datetime.fromtimestamp(first_time).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            (
                traffic_dic["source_ip"],
                traffic_dic["source_port"],
                traffic_dic["destination_ip"],
                traffic_dic["destination_port"],
                traffic_dic["transport_protocol"],
            ) = stream.split("_")

            # 初始化两个列表
            relative_timestamps = []
            payload_list = []
            for packet in tcpstream[stream]:
                time, payload, packet_num = packet
                relative_time = time - first_time
                relative_timestamps.append(f"{relative_time:.6f}")
                payload_list.append(payload)
            traffic_dic["timestamp"] = serialization(relative_timestamps)
            traffic_dic["payload"] = serialization(payload_list)
            traffic_dic["protocol"] = self.protocol
            traffic_dic["accessed_website"] = self.accessed_website
            traffic_dic["packet_length"] = len(payload_list)
            traffic_dic["packet_length_no_payload"] = len(
                [item for item in payload_list if item != "+0" and item != "-0"]
            )
            traffic_dic["collection_machine"] = self.collection_machine
            traffic_dic["pcap_path"] = self.pcap_path

            traffic.add_traffic(traffic_dic)

    def split_flow_to_database(self, min_packet_num=3, tcp_from_first_packet=False):
        # comment：介绍一下这个table
        tcpstream = self._process_pcap_file(tcp_from_first_packet)
        if tcpstream is None:
            return
        self._save_to_database(tcpstream, min_packet_num)

    def _trace_save_to_database(self, flow_num):
        host = self.db_config["host"]
        user = self.db_config["user"]
        port = self.db_config["port"]
        password = self.db_config["password"]
        database = self.db_config["database"]
        table = self.db_config["table"]

        traffic = TraceDB(host, port, user, password, database, table)
        traffic.connect()
        traffic_dic = {}

        traffic_dic["transport_protocol"], stream = self._process_pcap_file_nosplit()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        traffic_dic["entry_time"] = now
        first_time = stream[0][0]
        traffic_dic["capture_time"] = datetime.fromtimestamp(first_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        relative_timestamps = []
        payload_list = []
        for packet in stream:
            time, payload, _ = packet
            relative_time = time - first_time
            relative_timestamps.append(f"{relative_time:.6f}")
            payload_list.append(payload)
        traffic_dic["flownum"] = flow_num
        traffic_dic["timestamp"] = serialization(relative_timestamps)
        traffic_dic["payload"] = serialization(payload_list)
        traffic_dic["protocol"] = self.protocol
        traffic_dic["accessed_website"] = self.accessed_website
        traffic_dic["packet_length"] = len(payload_list)
        traffic_dic["packet_length_no_payload"] = len(
            [item for item in payload_list if item != "+0" and item != "-0"]
        )
        traffic_dic["collection_machine"] = self.collection_machine
        traffic_dic["pcap_path"] = self.pcap_path

        trace_id = traffic.add_trace(traffic_dic)

        return trace_id, first_time

    def pcap_to_database(self, min_packet_num=3, tcp_from_first_packet=False):
        # 入两个库，一个trace库，一个flow库
        # 1. 入trace库，得到trace的id
        # 2. 入flow库
        tcpstream = self._process_pcap_file(tcp_from_first_packet)
        if tcpstream is None:
            return
        trace_id, first_time = self._trace_save_to_database(len(tcpstream))
        self._save_to_database(tcpstream, min_packet_num, trace_id, first_time)


if __name__ == "__main__":
    db_config = {
        "host": "192.168.194.63",
        "port": 3306,
        "user": "root",
        "password": "aimafan",
        "database": "ConfuseWebpage",
        "table": "http",
    }

    pcapdb = PcapToDatabaseHandler(
        db_config,
        "http_20241216214756_141.164.58.43_jp_bilibili.com.pcap",
        "http",
        "bilibili.com",
        "jp_debian12",
    )

    pcapdb.pcap_to_database()
