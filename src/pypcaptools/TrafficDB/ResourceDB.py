import json
from typing import Any, Dict, List

from pypcaptools.TrafficDB.TrafficDB import TrafficDB

# 假设 TrafficDB 基类已经定义在别处或同一个文件中
# from pypcaptools.TrafficDB.TrafficDB import TrafficDB


class ResourceDB(TrafficDB):
    """
    管理 'resources' 数据表，用于存储 Flow 中承载的具体资源信息。
    """

    def __init__(
        self,
        host,
        port,
        user,
        password,
        database,
        table: str,
        flow_table_name: str,
        comment="存储Flow中的具体资源",
    ):
        super().__init__(host, port, user, password, database, table, comment)
        self.flow_table_name = flow_table_name

    def create_table(self):
        """
        根据新设计创建 'resources' 数据表，包含到 'flows' 表的外键。
        """
        # 注意：执行此操作前，'flows' 表必须已存在
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS `{self.table}` (
          `id` bigint NOT NULL AUTO_INCREMENT,
          `flow_id` bigint NOT NULL COMMENT '关联到flows表的ID',
          `stream_id` varchar(64) DEFAULT NULL COMMENT '流ID，可为纯数字或字符串，如 12 或 http1-0',
          `url` text,
          `http_status` smallint DEFAULT NULL,
          `content_type` varchar(255) DEFAULT NULL,
          `resource_size_bytes` bigint unsigned DEFAULT NULL,
          `server_packet_count` int unsigned DEFAULT NULL,
          `latency_ms` double DEFAULT NULL,
          `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (`id`),
          KEY `idx_flow_id` (`flow_id`),
          /* ### MODIFIED ###: 使用动态的父表名创建外键 */
          CONSTRAINT `fk_{self.table}_flow_id` FOREIGN KEY (`flow_id`) REFERENCES `{self.flow_table_name}` (`id`) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='{self.comment}';
        """
        print(
            f"正在为 '{self.table}' 执行建表操作 (关联到 '{self.flow_table_name}')..."
        )
        self.execute_commit(create_table_sql)
        print("数据表创建成功 (如果它尚不存在)。")

    def add_resource(self, resource_data: Dict[str, Any]) -> int:
        """
        插入单条 resource 记录。对于批量操作，强烈推荐使用 add_resources 方法。

        Args:
            resource_data (dict): 包含单条 resource 信息的字典。

        Returns:
            int: 新插入行的 ID。如果未插入，则返回 0。
        """
        columns = ", ".join(f"`{k}`" for k in resource_data.keys())
        placeholders = ", ".join(["%s"] * len(resource_data))

        insert_sql = f"INSERT INTO `{self.table}` ({columns}) VALUES ({placeholders})"
        values = tuple(resource_data.values())

        rows_affected = self.execute_commit(insert_sql, values)

        if rows_affected > 0:
            result = self.query("SELECT LAST_INSERT_ID() AS id")
            return result[0]["id"] if result else 0
        return 0

    def add_resources(self, resources_data: List[Dict[str, Any]]) -> int:
        """
        使用 executemany 高效地批量插入多条 resource 记录。

        Args:
            resources_data (List[Dict[str, Any]]): 包含多条 resource 数据的字典列表。
                                                    所有字典的键必须完全相同且顺序一致。

        Returns:
            int: 成功插入的记录总数。
        """
        if not resources_data:
            return 0

        # 以第一个数据字典为模板，构建 SQL 语句
        sample_row = resources_data[0]
        columns = ", ".join(f"`{k}`" for k in sample_row.keys())
        placeholders = ", ".join(["%s"] * len(sample_row))
        insert_sql = f"INSERT INTO `{self.table}` ({columns}) VALUES ({placeholders})"

        # 将所有值转换为元组列表
        values_list = [tuple(row.values()) for row in resources_data]

        # 执行批量插入
        if self.cursor is None or self.conn is None:
            raise RuntimeError("数据库连接未建立。")
        self.cursor.executemany(insert_sql, values_list)
        self.conn.commit()

        return self.cursor.rowcount
