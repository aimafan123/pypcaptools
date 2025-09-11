from pypcaptools.Flow import Flow
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
        self.traffic.connect()  # 根据您的连接管理逻辑，此行可能是必需的

    def count_traces(self, condition: str = "1 == 1") -> int:
        return super().count_flows(self.table + "_trace", condition)

    def get_value_list_unique(self, field: str, condition: str = "1 == 1") -> list:
        return super().get_value_list_unique(self.table + "_trace", field, condition)

    def get_value_list(self, field: str, condition: str = "1 == 1") -> list:
        return super().get_value_list(self.table + "_trace", field, condition)

    def get_trace_flow(self, condition: str = "1 == 1") -> dict:
        trace_id_list = self.get_value_list("id", condition)
        trace_dict = {}
        flow_table_name = self.table + "_flow"

        for trace_id in trace_id_list:
            flow_condition = f"trace_id == {trace_id}"

            payload_seq_list = super().get_payload_sequence(
                flow_table_name, flow_condition
            )
            timestamp_seq_list = super().get_timestamp_sequence(
                flow_table_name, flow_condition
            )
            direction_seq_list = super().get_direction_sequence(
                flow_table_name, flow_condition
            )

            flows = []
            if not (
                len(payload_seq_list)
                == len(timestamp_seq_list)
                == len(direction_seq_list)
            ):
                print(f"[Warning] Trace ID {trace_id} 的序列长度不匹配，已跳过。")
                continue

            for i in range(len(payload_seq_list)):
                flows.append(
                    Flow.from_sequences(
                        payload_seq_list[i],
                        timestamp_seq_list[i],
                        direction_seq_list[i],
                    )
                )
            trace_dict[trace_id] = flows

        return trace_dict

    def get_trace_flow_payload_sequence(self, condition: str = "1 == 1") -> dict:
        trace_id_list = self.get_value_list("id", condition)
        payload_dict = {}
        flow_table_name = self.table + "_flow"
        for trace_id in trace_id_list:
            payload_list = super().get_payload_sequence(
                flow_table_name, f"trace_id == {trace_id}"
            )
            payload_dict[trace_id] = payload_list
        return payload_dict

    def get_trace_flow_timestamp_sequence(self, condition: str = "1 == 1") -> dict:
        trace_id_list = self.get_value_list("id", condition)
        timestamp_dict = {}
        flow_table_name = self.table + "_flow"
        for trace_id in trace_id_list:
            timestamp_list = super().get_timestamp_sequence(
                flow_table_name, f"trace_id == {trace_id}"
            )
            timestamp_dict[trace_id] = timestamp_list
        return timestamp_dict

    def get_trace_flow_direction_sequence(self, condition: str = "1 == 1") -> dict:
        trace_id_list = self.get_value_list("id", condition)
        direction_dict = {}
        flow_table_name = self.table + "_flow"
        for trace_id in trace_id_list:
            direction_list = super().get_direction_sequence(
                flow_table_name, f"trace_id == {trace_id}"
            )
            direction_dict[trace_id] = direction_list
        return direction_dict

    @property
    def table_columns(self) -> list:
        return super().table_columns(self.table)
