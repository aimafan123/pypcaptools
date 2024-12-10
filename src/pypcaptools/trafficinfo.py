# 1. 某个table中，满足某些条件的流的个数

import re

from pypcaptools.mysql import TrafficDB
from pypcaptools.util import DBConfig, deserialization


def condition_parse(condition_str):
    """
    统计MySQL表中满足条件的条目数量（支持复杂字符串条件）。

    :param table: 目标表名
    :param condition_str: 条件字符串，例如 "name == '小方' and (age > 2 or country == 'CN')"
    :return: 满足条件的条目数量
    """
    # 替换运算符为SQL格式
    if condition_str == "1 == 1":
        return "1 = 1", None
    condition_str = condition_str.replace("==", "=").replace("!=", "<>")

    # 提取字段、操作符和值
    pattern = r"(\w+)\s*([<>=!]+)\s*([^\s()]+)"
    matches = re.findall(pattern, condition_str)

    # 将提取的字段和值分开
    sql_conditions = condition_str
    values = []
    for field, operator, value in matches:
        placeholder = "%s"
        sql_conditions = sql_conditions.replace(
            f"{field} {operator} {value}", f"`{field}` {operator} {placeholder}"
        )
        # 处理字符串值（去掉引号）
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        values.append(value)

    return sql_conditions, values


class TrafficInfo:
    def __init__(self, db_config: DBConfig):
        """
        注意，这里的TrafficInfo是以database为单位的
        db_config = {"host": ,"port": ,"user": ,"password": , "database": }
        """
        self.db_config = db_config

    def use_table(self, table) -> None:
        host = self.db_config["host"]
        user = self.db_config["user"]
        port = self.db_config["port"]
        password = self.db_config["password"]
        database = self.db_config["database"]
        self.table = table
        self.traffic = TrafficDB(host, port, user, password, database, self.table)
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
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT COUNT(*) FROM {self.table} WHERE {sql_conditions}"
        result = self.traffic.execute(sql, values)
        return result[0]

    def get_value_list_unique(self, field: str, condition: str = "1 == 1") -> list:
        """
        从表中获取指定列的所有唯一值，并返回字符串列表。

        该函数执行一个查询，选取指定列中所有不重复的值，结果返回为一个字符串列表。

        :param column_name: 需要查询的列名（字符串类型）
        :return: 返回一个包含唯一字符串的列表
        """
        assert field in self.table_columns, f"Field must be one of {self.table_columns}"
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT DISTINCT {field} FROM {self.table} WHERE {sql_conditions};"
        result = self.traffic.execute(sql, values)
        return result

    def get_payload(self, condition: str = "1 == 1") -> list:
        # 获得满足一些条件的流的payload序列
        # 返回payload序列列表
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT payload FROM {self.table} WHERE {sql_conditions}"
        result = self.traffic.execute(sql, values)
        payload = [deserialization(x) for x in result]
        return payload

    def get_timestamp(self, condition: str = "1 == 1") -> list:
        # 获得满足一些条件的流的时间戳序列（这里的时间是相对时间）
        # 返回时间戳序列列表
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT timestamp FROM {self.table} WHERE {sql_conditions}"
        result = self.traffic.execute(sql, values)
        payload = [deserialization(x) for x in result]
        return payload

    def get_value_list(self, field: str, condition: str = "1 == 1") -> list:
        # 获得满足一些条件的流的字段值列表
        # 返回字段列表
        assert field in self.table_columns, f"Field must be one of {self.table_columns}"
        sql_conditions, values = condition_parse(condition)
        sql = f"SELECT {field} FROM {self.table} WHERE {sql_conditions}"
        result = self.traffic.execute(sql, values)
        return result

    @property
    def table_columns(self) -> list:
        """
        获取数据库表的列信息及对应的注释。

        Returns:
            list: 包含表列名
        """
        original_data = self.traffic.get_table_columns()
        field_list = []
        for item in original_data:
            field_list.append(item["Field"])

        return field_list


if __name__ == "__main__":
    pass
