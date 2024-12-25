from pypcaptools.TrafficDB.TraceDB import TraceDB
from pypcaptools.TrafficInfo.TrafficInfo import TrafficInfo
from pypcaptools.util import DBConfig


class TraceInfo(TrafficInfo):
    def __init__(self, db_config: DBConfig):
        super().__init__(db_config)

    def use_table(self, table) -> None:
        super().use_table(table)
        self.traffic = TraceDB(
            self.host, self.port, self.user, self.password, self.database, self.table
        )
        self.traffic.connect()

    def count_flows(self, condition: str = "1 == 1") -> int:
        """
        这里condition可以包含多个语句，每个语句由field, operator, value三部分组成，语句之间使用 and 或者 or 连接，注意，mysql中and的优先级高于or的优先级
        field为table的头，可以使用table_columns获得
        operator为运算符，包括==, >, <, <=, >=, !=
        value为具体的值
        例： packet_length >= 10 and accessed_website == 163.com
        Return: int 满足条件的流的数量
        """
        return super().count_flows(self.table + "_trace", condition)

    def get_value_list_unique(self, field: str, condition: str = "1 == 1") -> list:
        """
        从表中获取指定列的所有唯一值，并返回字符串列表。

        该函数执行一个查询，选取指定列中所有不重复的值，结果返回为一个字符串列表。

        :param column_name: 需要查询的列名（字符串类型）
        :return: 返回一个包含唯一字符串的列表
        """
        return super().get_value_list_unique(self.table + "_trace", field, condition)

    def get_payload(self, condition: str = "1 == 1") -> list:
        # 获得满足一些条件的流的payload序列
        # 返回payload序列列表
        return super().get_payload(self.table + "_trace", condition)

    def get_timestamp(self, condition: str = "1 == 1") -> list:
        # 获得满足一些条件的流的时间戳序列（这里的时间是相对时间）
        # 返回时间戳序列列表
        return super().get_timestamp(self.table + "_trace", condition)

    def get_value_list(self, field: str, condition: str = "1 == 1") -> list:
        # 获得满足一些条件的流的字段值列表
        # 返回字段列表
        return super().get_value_list(self.table + "_trace", field, condition)

    # def get_trace_flow_payload(self, condition: str = "1 == 1") -> list:
    #     # 返回属于同一个trace的所有flow的payload
    #     # 返回一个列表，列表中有若干列表，每个列表是flow的payload序列
    #     sql_conditions, values = condition_parse(condition)
    #     sql = f"SELECT payload FROM {self.table + "_flow"} WHERE {sql_conditions} "
    #     result = self.traffic.execute(sql, values)
    #     payload = [deserialization(x) for x in result]
    #     return payload

    def get_trace_flow_payload(self, condition: str = "1 == 1") -> list:
        # 返回属于同一个trace的所有flow的payload
        # 返回一个字典，字典的键是trace_id，值是一个列表，列表中嵌套着列表，包括了flow的payload序列
        # 得到符合条件的trace_id
        trace_id_list = self.get_value_list("id", condition)
        payload_dict = {}
        for trace_id in trace_id_list:
            payload_list = super().get_payload(
                self.table + "_flow", f"trace_id == {trace_id}"
            )
            payload_dict[trace_id] = payload_list
        return payload_dict

    def get_trace_flow_timestamp(self, condition: str = "1 == 1") -> list:
        # TODO
        # 返回属于同一个trace的所有flow的timestamp
        # 返回一个字典，字典的键是trace_id，值是一个列表，列表中嵌套着列表，包括了flow的timestamp序列
        # 得到符合条件的trace_id
        trace_id_list = self.get_value_list("id", condition)
        timestamp_dict = {}
        for trace_id in trace_id_list:
            timestamp_list = super().get_timestamp(
                self.table + "_flow", f"trace_id == {trace_id}"
            )
            timestamp_dict[trace_id] = timestamp_list
        return timestamp_dict

    @property
    def table_columns(self) -> list:
        return super().table_columns(self.table + "_trace")


if __name__ == "__main__":
    pass
