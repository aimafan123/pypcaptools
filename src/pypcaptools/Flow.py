from typing import List

from pypcaptools.Packet import Packet


class Flow:
    def __init__(self, packets: List[Packet] = []):
        """
        初始化 Flow 类的实例

        :param packets: 包含该流的所有数据包的列表
        """
        self.packets = packets
        if len(packets) != 0:
            self.start_time = min(packet.time for packet in packets)
            self.end_time = max(packet.time for packet in packets)
            self.total_payload = sum(abs(packet.payload) for packet in packets)
        else:
            self.start_time = self.end_time = self.total_payload = 0

    @classmethod
    def from_payload_timestamp_list(cls, payload: List, timestamp: List):
        if len(payload) != len(timestamp):
            raise ValueError(
                "The length of payload and timestamp lists must be the same."
            )
        packets = []
        for i in range(len(payload)):
            packets.append(Packet(timestamp[i], payload[i]))
        return cls(packets)

    @property
    def duration(self) -> float:
        """流的持续时间，即流的结束时间减去开始时间"""
        return self.end_time - self.start_time

    def payload_sequence(self, dont_include_zero_payload=False):
        payload_sequence = []
        for packet in self.packets:
            if dont_include_zero_payload and packet.is_zero:
                continue
            payload_sequence.append(packet.payload)
        return payload_sequence

    def timestamp_sequence(self, dont_include_zero_payload=False, from_zero_time=True):
        timestamp_sequence = []
        first_time = self.packets[0].time
        for packet in self.packets:
            if dont_include_zero_payload and packet.is_zero:
                continue
            if from_zero_time:
                timestamp_sequence.append(packet.time - first_time)
            else:
                timestamp_sequence.append(packet.time)
        return timestamp_sequence

    def dirction_sequence(self, dont_include_zero_payload=False):
        dirction_sequence = []
        for packet in self.packets:
            if dont_include_zero_payload and packet.is_zero:
                continue
            dirction_sequence.append(packet.direction)
        return dirction_sequence

    def flow_length(self, dont_include_zero_payload=False):
        return len(self.payload_sequence(dont_include_zero_payload))

    def add_packet(self, packet: Packet):
        """向流中添加一个新的数据包，并更新流的相关属性"""
        self.packets.append(packet)
        self.start_time = min(self.start_time, packet.time)
        self.end_time = max(self.end_time, packet.time)
        self.total_payload += packet.payload

    def __repr__(self) -> str:
        return (
            f"Flow(start_time={self.start_time}, end_time={self.end_time}, "
            f"total_payload={self.total_payload}, num_packets={len(self.packets)})"
        )

    def __str__(self) -> str:
        return (
            f"Flow from {self.start_time} to {self.end_time}, "
            f"Total Payload: {self.total_payload}, "
            f"Number of Packets: {len(self.packets)}"
        )
