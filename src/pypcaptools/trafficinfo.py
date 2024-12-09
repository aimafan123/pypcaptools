# 1. 某个table中，满足某些条件的流的个数

import re

from pypcaptools.mysql import TrafficDB


def condition_parse(table, condition_str):
    """
    统计MySQL表中满足条件的条目数量（支持复杂字符串条件）。

    :param table: 目标表名
    :param condition_str: 条件字符串，例如 "name == '小方' and (age > 2 or country == 'CN')"
    :return: 满足条件的条目数量
    """
    # 替换运算符为SQL格式
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

    # 拼接最终SQL
    sql = f"SELECT COUNT(*) FROM {table} WHERE {sql_conditions}"

    return sql, values


class TrafficInfo:
    def __init__(self, db_config: dict):
        """
        注意，这里的TrafficInfo是以database为单位的
        db_config = {"host": ,"port": ,"user": ,"password": , "database": }
        """
        self.db_config = db_config

    def use_table(self, table):
        host = self.db_config["host"]
        user = self.db_config["user"]
        port = self.db_config["port"]
        password = self.db_config["password"]
        database = self.db_config["database"]
        self.table = table
        self.traffic = TrafficDB(host, port, user, password, database, self.table)
        self.traffic.connect()

    def count_flows(self, condition: str):
        """
        这里condition可以包含多个语句，每个语句由field, operator, value三部分组成，语句之间使用 and 或者 or 连接，注意，mysql中and的优先级高于or的优先级
        field为table的头，可以使用table_columns获得
        operator为运算符，包括==, >, <, <=, >=, !=
        value为具体的值
        例： packet_length >= 10 and accessed_website == 163.com
        Return: int 满足条件的流的数量
        """
        sql, values = condition_parse(self.table, condition)
        result = self.traffic.execute(sql, values)
        return result[0]

    def fetch_all_values(self, column_name):
        """
        从表中获取指定列的所有唯一值，并返回字符串列表。

        该函数执行一个查询，选取指定列中所有不重复的值，结果返回为一个字符串列表。

        :param column_name: 需要查询的列名（字符串类型）
        :return: 返回一个包含唯一字符串的列表
        """
        sql = f"SELECT DISTINCT {column_name} FROM {self.table};"
        result = self.traffic.execute(sql)
        return result

    @property
    def table_columns(self) -> list:
        """
        获取数据库表的列信息及对应的注释。

        Returns:
            list: 包含表列名及其注释的字典列表。
                {
                    'Field': 列名 (str),
                    'Comment': 列注释 (str)
                }
        """
        original_data = self.traffic.get_table_columns()
        transformed_data = [
            {"Field": item["Field"], "Comment": item["Comment"]}
            for item in original_data
        ]

        return transformed_data


if __name__ == "__main__":
    pass
