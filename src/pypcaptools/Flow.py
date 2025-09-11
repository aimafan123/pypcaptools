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
            # 使用 abs(packet.payload) 依然有效，因为它等同于 packet.size
            self.total_payload = sum(abs(packet.payload) for packet in packets)
        else:
            self.start_time = self.end_time = self.total_payload = 0

    @classmethod
    def from_sequences(
        cls,
        size_sequence: List[int],
        timestamp_sequence: List[float],
        direction_sequence: List[int],
    ):
        """
        通过大小、时间戳和方向序列列表创建 Flow 实例。
        这是处理新数据格式的核心方法。
        """
        if not (
            len(size_sequence) == len(timestamp_sequence) == len(direction_sequence)
        ):
            raise ValueError("大小、时间戳和方向列表的长度必须相同。")
        packets = []
        for i in range(len(size_sequence)):
            packets.append(
                Packet(timestamp_sequence[i], size_sequence[i], direction_sequence[i])
            )
        return cls(packets)

    @property
    def duration(self) -> float:
        """流的持续时间，即流的结束时间减去开始时间"""
        return self.end_time - self.start_time

    def payload_sequence(self, dont_include_zero_payload=False) -> List[int]:
        """返回带符号的有效载荷序列"""
        payload_seq = []
        for packet in self.packets:
            if dont_include_zero_payload and packet.is_zero:
                continue
            payload_seq.append(packet.payload)
        return payload_seq

    def timestamp_sequence(
        self, dont_include_zero_payload=False, from_zero_time=True
    ) -> List[float]:
        """返回时间戳序列"""
        timestamp_seq = []
        if not self.packets:
            return timestamp_seq

        first_time = self.packets[0].time
        for packet in self.packets:
            if dont_include_zero_payload and packet.is_zero:
                continue
            if from_zero_time:
                timestamp_seq.append(packet.time - first_time)
            else:
                timestamp_seq.append(packet.time)
        return timestamp_seq

    def direction_sequence(self, dont_include_zero_payload=False) -> List[int]:
        """返回方向序列"""
        direction_seq = []
        for packet in self.packets:
            if dont_include_zero_payload and packet.is_zero:
                continue
            direction_seq.append(packet.direction)
        return direction_seq

    def flow_length(self, dont_include_zero_payload=False) -> int:
        """返回流中数据包的数量"""
        # 优化：直接计算，而不是生成一个中间列表
        if not dont_include_zero_payload:
            return len(self.packets)
        return sum(1 for p in self.packets if not p.is_zero)

    def add_packet(self, packet: Packet):
        """向流中添加一个新的数据包，并更新流的相关属性"""
        self.packets.append(packet)
        # 初始为空流的情况
        if len(self.packets) == 1:
            self.start_time = packet.time
            self.end_time = packet.time
            self.total_payload = 0

        self.start_time = min(self.start_time, packet.time)
        self.end_time = max(self.end_time, packet.time)
        self.total_payload += packet.size  # 累加无符号大小

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
