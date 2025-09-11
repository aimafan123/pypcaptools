from pypcaptools.TrafficDB.ResourceDB import ResourceDB
from pypcaptools.TrafficInfo.TrafficInfo import TrafficInfo
from pypcaptools.util import DBConfig


class ResourceInfo(TrafficInfo):
    def __init__(self, db_config: DBConfig):
        super().__init__(db_config)

    def use_table(self, table) -> None:
        super().use_table(table)
        # ResourceDB 初始化需要 flow_table_name
        # 这里的逻辑假设 resource 表名类似于 "some_trace_table_resource"
        self.traffic = ResourceDB(
            self.host,
            self.port,
            self.user,
            self.password,
            self.database,
            self.table,
            table + "_flow",
        )
        self.traffic.connect()  # 根据您的连接管理逻辑，此行可能是必需的

    def count_resources(self, condition: str = "1 == 1") -> int:
        return super().count_flows(self.table + "_resource", condition)

    def get_value_list_unique(self, field: str, condition: str = "1 == 1") -> list:
        return super().get_value_list_unique(self.table + "_resource", field, condition)

    def get_value_list(self, field: str, condition: str = "1 == 1") -> list:
        return super().get_value_list(self.table + "_resource", field, condition)

    def get_resources_by_flow_id(self, flow_id: int) -> list:
        """根据flow_id获取该流的所有资源"""
        return self.get_value_list("resource_size_bytes", f"flow_id == {flow_id}")

    @property
    def table_columns(self) -> list:
        return super().table_columns(self.table + "_resource")
