import ast
import json
import re

from pypcaptools.TrafficDB.ResourceDB import ResourceDB
from pypcaptools.TrafficInfo.TrafficInfo import TrafficInfo
from pypcaptools.TrafficInfo.TrafficInfo import condition_parse
from pypcaptools.util import DBConfig


def _parse_json_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode()
    if not isinstance(value, str):
        return value

    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(value)
            return parsed if parsed is not None else []
        except (ValueError, SyntaxError, TypeError, json.JSONDecodeError):
            continue
    return []


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

    def get_feature_inputs(self, condition: str = "1 == 1") -> list:
        """
        Return resource rows with the flow/trace fields needed for feature extraction.

        The condition is applied to the resource table fields.
        """
        resource_table = f"{self.table}_resource"
        flow_table = f"{self.table}_flow"
        trace_table = f"{self.table}_trace"
        sql_conditions, values = condition_parse(condition)
        sql_conditions = re.sub(r"`([^`]+)`", r"r.`\1`", sql_conditions)

        sql = f"""
        SELECT
            r.id AS resource_id,
            r.flow_id,
            f.trace_id,
            t.site_id,
            t.accessed_website,
            r.resource_index,
            r.stream_id,
            r.url,
            r.http_status,
            r.content_type,
            r.request_size_bytes,
            r.resource_size_bytes,
            r.headers_packet_num,
            r.headers_flow_packet_num,
            r.request_packet_count,
            r.server_packet_count,
            r.request_packet_nums,
            r.response_packet_nums,
            r.request_flow_packet_nums,
            r.response_flow_packet_nums,
            r.trace_packet_indices AS resource_trace_packet_indices,
            r.request_start_ts,
            r.response_start_ts,
            r.response_end_ts,
            r.ttfb_ms,
            r.duration_ms,
            f.trace_packet_indices AS flow_trace_packet_indices,
            f.timestamps_seq AS flow_timestamps_seq,
            f.payload_seq AS flow_payload_seq,
            f.direction_seq AS flow_direction_seq
        FROM `{resource_table}` r
        JOIN `{flow_table}` f ON r.flow_id = f.id
        JOIN `{trace_table}` t ON f.trace_id = t.id
        WHERE {sql_conditions}
        ORDER BY f.trace_id, r.flow_id, r.resource_index, r.id
        """
        rows = self.traffic.query(sql, values)

        json_fields = [
            "request_packet_nums",
            "response_packet_nums",
            "request_flow_packet_nums",
            "response_flow_packet_nums",
            "resource_trace_packet_indices",
            "flow_trace_packet_indices",
            "flow_timestamps_seq",
            "flow_payload_seq",
            "flow_direction_seq",
        ]
        for row in rows:
            for field in json_fields:
                row[field] = _parse_json_list(row.get(field))
        return rows

    @property
    def table_columns(self) -> list:
        return super().table_columns(self.table + "_resource")
