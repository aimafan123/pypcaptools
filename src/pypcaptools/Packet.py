class Packet:
    def __init__(self, time, payload):
        """
        初始化 Packet 类的实例

        :param time: 数据包的时间戳
        :param payload: 数据包的有效载荷（带方向）
        :param direction: 数据包的方向（+1、-1）
        """
        self.time = float(time)
        try:
            self.payload = int(payload)
        except ValueError:
            raise ValueError(f"Invalid payload value: {payload}")
        if self.payload == 0:
            self.direction = 0
        elif self.payload > 0:
            self.direction = 1
        else:
            self.direction = -1

    @property
    def is_zero(self):
        return int(self.payload) == 0

    def __repr__(self):
        return f"Packet(time={self.time}, direction={self.direction}, payload={repr(self.payload)})"

    def __str__(self):
        return f"Time: {self.time}, Direction: {self.direction}, Payload: {repr(self.payload)}"

    def __eq__(self, other) -> bool:
        if isinstance(other, Packet):
            return (self.time, self.payload) == (other.time, other.payload)
        return False

    def __hash__(self) -> int:
        return hash((self.time, self.payload))


if __name__ == "__main__":
    packet = Packet(2.23132, "-233")
    print(packet.is_zero)
