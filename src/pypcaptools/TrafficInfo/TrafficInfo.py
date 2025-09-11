import ast
import re

# 假设您的 util 模块中除了 deserialization 外还有其他功能
from pypcaptools.util import DBConfig


# condition_parse 函数保持不变
def condition_parse(condition_str):
    if condition_str == "1 == 1":
        return "1 = 1", None
    condition_str = condition_str.replace("==", "=").replace("!=", "<>")
    pattern = r"(\w+)\s*([<>=!]+)\s*([^\s()]+)"
    matches = re.findall(pattern, condition_str)
    sql_conditions = condition_str
    values = []
    for field, operator, value in matches:
        placeholder = "%s"
        sql_conditions = sql_conditions.replace(
            f"{field} {operator} {value}", f"`{field}` {operator} {placeholder}"
        )
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        values.append(value)
    return sql_conditions, values


class TrafficInfo:
    def __init__(self, db_config: DBConfig):
        self.db_config = db_config
        self.traffic = None

    def use_table(self, table) -> None:
        self.host = self.db_config["host"]
        self.user = self.db_config["user"]
        self.port = self.db_config["port"]
        self.password = self.db_config["password"]
        self.database = self.db_config["database"]
        self.table = table

    def count_flows(self, table_name, condition: str = "1 == 1") -> int:
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT COUNT(*) as total_count FROM {table_name} WHERE {sql_conditions}"
        result = self.traffic.query(sql, values)
        if result:
            return result[0]["total_count"]
        return 0

    def get_value_list_unique(
        self, table_name, field: str, condition: str = "1 == 1"
    ) -> list:
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT DISTINCT `{field}` FROM {table_name} WHERE {sql_conditions};"
        result_dicts = self.traffic.query(sql, values)
        return [row[field] for row in result_dicts]

    def get_payload_sequence(self, table_name, condition: str = "1 == 1") -> list:
        """(修正) 直接返回数据库驱动解析后的Python列表，不再手动反序列化"""
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT payload_seq FROM {table_name} WHERE {sql_conditions}"
        result_dicts = self.traffic.query(sql, values)
        # 直接返回数据库驱动解析后的Python列表
        return [ast.literal_eval(row["payload_seq"]) for row in result_dicts]

    def get_timestamp_sequence(self, table_name, condition: str = "1 == 1") -> list:
        """(修正) 直接返回数据库驱动解析后的Python列表，不再手动反序列化"""
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT timestamps_seq FROM {table_name} WHERE {sql_conditions}"
        result_dicts = self.traffic.query(sql, values)
        # 直接返回数据库驱动解析后的Python列表
        return [ast.literal_eval(row["timestamps_seq"]) for row in result_dicts]

    def get_direction_sequence(self, table_name, condition: str = "1 == 1") -> list:
        """(修正) 直接返回数据库驱动解析后的Python列表，不再手动反序列化"""
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT direction_seq FROM {table_name} WHERE {sql_conditions}"
        result_dicts = self.traffic.query(sql, values)
        # 直接返回数据库驱动解析后的Python列表
        return [ast.literal_eval(row["direction_seq"]) for row in result_dicts]

    def get_value_list(self, table_name, field: str, condition: str = "1 == 1") -> list:
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT `{field}` FROM {table_name} WHERE {sql_conditions}"
        result_dicts = self.traffic.query(sql, values)
        return [row[field] for row in result_dicts]

    def table_columns(self, table_name) -> list:
        original_data = self.traffic.get_table_columns(table_name)
        return [item["Field"] for item in original_data]
