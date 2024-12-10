from datetime import datetime

from pypcaptools.mysql import TrafficDB
from pypcaptools.pcaphandler import PcapHandler
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

    def _save_to_database(self, tcpstream, min_packet_num, comment):
        host = self.db_config["host"]
        user = self.db_config["user"]
        port = self.db_config["port"]
        password = self.db_config["password"]
        database = self.db_config["database"]
        table = self.db_config["table"]

        traffic = TrafficDB(host, port, user, password, database, table, comment)
        traffic.connect()

        for stream in tcpstream:
            if len(tcpstream[stream]) <= min_packet_num:
                continue
            traffic_dic = {}
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            traffic_dic["entry_time"] = now
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
        tcpstream = self._process_pcap_file(self.input_pcap_file, tcp_from_first_packet)
        if tcpstream is None:
            return
        self._save_to_database(tcpstream, min_packet_num, self.comment)


if __name__ == "__main__":
    pass
