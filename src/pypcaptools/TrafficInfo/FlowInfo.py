from pypcaptools.TrafficDB.FlowDB import FlowDB
from pypcaptools.TrafficInfo.TrafficInfo import TrafficInfo
from pypcaptools.util import DBConfig


class FlowInfo(TrafficInfo):
    def __init__(self, db_config: DBConfig):
        super().__init__(db_config)

    def use_table(self, table) -> None:
        super().use_table(table)
        # FlowDB 初始化需要 trace_table_name
        # 这里的逻辑假设 flow 表名类似于 "some_trace_table_flow"
        self.traffic = FlowDB(
            self.host,
            self.port,
            self.user,
            self.password,
            self.database,
            self.table,
            table + "_trace",
        )
        self.traffic.connect()  # 根据您的连接管理逻辑，此行可能是必需的

    def count_flows(self, condition: str = "1 == 1") -> int:
        return super().count_flows(self.table + "_flow", condition)

    def get_value_list_unique(self, field: str, condition: str = "1 == 1") -> list:
        return super().get_value_list_unique(self.table + "_flow", field, condition)

    def get_payload_sequence(self, condition: str = "1 == 1") -> list:
        return super().get_payload_sequence(self.table + "_flow", condition)

    def get_timestamp_sequence(self, condition: str = "1 == 1") -> list:
        return super().get_timestamp_sequence(self.table + "_flow", condition)

    def get_direction_sequence(self, condition: str = "1 == 1") -> list:
        return super().get_direction_sequence(self.table + "_flow", condition)

    def get_value_list(self, field: str, condition: str = "1 == 1") -> list:
        return super().get_value_list(self.table + "_flow", field, condition)

    @property
    def table_columns(self) -> list:
        return super().table_columns(self.table + "_flow")
