class Packet:
    def __init__(self, time: float, size: int, direction: int):
        """
        初始化 Packet 类的实例

        :param time: 数据包的时间戳
        :param size: 数据包的有效载荷大小（无符号）
        :param direction: 数据包的方向（1 表示出，-1 表示入）
        """
        self.time = float(time)
        self.size = abs(int(size))

        # 标准化方向：如果大小为0，方向也为0
        if self.size == 0:
            self.direction = 0
        else:
            self.direction = int(direction)
            if self.direction not in [1, -1]:
                raise ValueError(
                    f"对于非零载荷，方向必须是 1 或 -1，但得到的是 {self.direction}"
                )

    @property
    def payload(self) -> int:
        """返回带方向的有效载荷 (signed payload)"""
        return self.size * self.direction

    @property
    def is_zero(self) -> bool:
        """检查数据包的有效载荷是否为零"""
        return self.size == 0

    def __repr__(self) -> str:
        # repr() 用于明确地重建对象，显示带符号的 payload 更直观
        return f"Packet(time={self.time}, payload={self.payload})"

    def __str__(self) -> str:
        # str() 用于更友好的用户显示
        return f"Time: {self.time}, Direction: {self.direction}, Size: {self.size}"

    def __eq__(self, other) -> bool:
        if isinstance(other, Packet):
            return (self.time, self.payload) == (other.time, other.payload)
        return False

    def __hash__(self) -> int:
        return hash((self.time, self.payload))
