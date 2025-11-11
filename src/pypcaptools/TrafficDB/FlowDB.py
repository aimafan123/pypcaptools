import json
from typing import Any, Dict, List

import mysql.connector

from pypcaptools.TrafficDB.TrafficDB import TrafficDB


class FlowDB(TrafficDB):
    """
    管理 'flows' 数据表，用于存储 Trace 中的单个网络流。
    """

    def __init__(
        self,
        host,
        port,
        user,
        password,
        database,
        table: str,
        trace_table_name: str,
        comment="存储Trace中的单个网络流 (Flow)",
    ):
        super().__init__(host, port, user, password, database, table, comment)
        self.trace_table_name = trace_table_name

    def create_table(self):
        """
        根据新设计创建 'flows' 数据表，包含到 'traces' 表的外键。
        """
        # 注意：执行此操作前，'traces' 表必须已存在
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS `{self.table}` (
          `id` bigint NOT NULL AUTO_INCREMENT,
          `trace_id` bigint NOT NULL COMMENT '关联到traces表的ID',
          `source_ip` varchar(45) NOT NULL,
          `destination_ip` varchar(45) NOT NULL,
          `source_port` smallint unsigned NOT NULL,
          `destination_port` smallint unsigned NOT NULL,
          `transport_protocol` enum('TCP','UDP') NOT NULL,
          `sni` varchar(255) DEFAULT NULL,
          `flow_start_time_ms` double DEFAULT NULL,
          `flow_duration_ms` double DEFAULT NULL,
          `timestamps_seq` JSON,
          `payload_seq` JSON NOT NULL,
          `direction_seq` JSON NOT NULL,
          `http_version` varchar(16) DEFAULT NULL COMMENT 'HTTP协议版本，如 http1.1 或 http2',
          `trace_packet_indices` json DEFAULT NULL COMMENT '本flow包含的数据包在traces主序列中的索引列表 (JSON数组, e.g., [0, 2, 3, 7])',
          `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (`id`),
          KEY `idx_trace_id` (`trace_id`),
          /* ### MODIFIED ###: 使用动态的父表名创建外键 */
          CONSTRAINT `fk_{self.table}_trace_id` FOREIGN KEY (`trace_id`) REFERENCES `{self.trace_table_name}` (`id`) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='{self.comment}';
        """
        print(
            f"正在为 '{self.table}' 执行建表操作 (关联到 '{self.trace_table_name}')..."
        )
        self.execute_commit(create_table_sql)
        print("数据表创建成功 (如果它尚不存在)。")

    def add_flow(self, flow_data: Dict[str, Any]) -> int:
        """
        插入单条 flow 记录。对于批量操作，推荐使用 add_flows 方法。

        Args:
            flow_data (dict): 包含单条 flow 信息的字典。

        Returns:
            int: 新插入行的 ID。如果未插入，则返回 0。
        """
        data_to_insert = flow_data.copy()
        json_fields = [
            "timestamps_seq",
            "payload_seq",
            "direction_seq",
            "trace_packet_indices",
        ]
        for field in json_fields:
            if field in data_to_insert and data_to_insert[field] is not None:
                if not isinstance(data_to_insert[field], str):
                    data_to_insert[field] = json.dumps(data_to_insert[field])

        columns = ", ".join(f"`{k}`" for k in data_to_insert.keys())
        placeholders = ", ".join(["%s"] * len(data_to_insert))

        # 对于 flow 表，一般直接 INSERT，因为没有业务上的唯一键（除了主键）
        insert_sql = f"INSERT INTO `{self.table}` ({columns}) VALUES ({placeholders})"
        values = tuple(data_to_insert.values())

        rows_affected = self.execute_commit(insert_sql, values)

        if rows_affected > 0:
            result = self.query("SELECT LAST_INSERT_ID() AS id")
            return result[0]["id"] if result else 0
        return 0

    def add_flows(self, flows_data: List[Dict[str, Any]]) -> int:
        """
        使用 executemany 高效地批量插入多条 flow 记录。

        Args:
            flows_data (List[Dict[str, Any]]): 包含多条 flow 数据的字典列表。
                                              注意：列表中所有字典的键必须完全相同且顺序一致。

        Returns:
            int: 成功插入的记录总数。
        """
        if not flows_data:
            return 0

        # 预处理所有记录的 JSON 字段
        json_fields = [
            "timestamps_seq",
            "payload_seq",
            "direction_seq",
            "trace_packet_indices",
        ]
        processed_data = []
        for row in flows_data:
            processed_row = row.copy()
            for field in json_fields:
                if field in processed_row and processed_row[field] is not None:
                    if not isinstance(processed_row[field], str):
                        processed_row[field] = json.dumps(processed_row[field])
            processed_data.append(processed_row)

        # 以第一个数据字典为模板，构建 SQL 语句
        sample_row = processed_data[0]
        columns = ", ".join(f"`{k}`" for k in sample_row.keys())
        placeholders = ", ".join(["%s"] * len(sample_row))
        insert_sql = f"INSERT INTO `{self.table}` ({columns}) VALUES ({placeholders})"

        # 将所有值转换为元组列表，以供 executemany 使用
        values_list = [tuple(row.values()) for row in processed_data]

        # 执行批量插入
        if self.cursor is None or self.conn is None:
            raise RuntimeError("数据库连接未建立。")
        self.cursor.executemany(insert_sql, values_list)
        self.conn.commit()

        return self.cursor.rowcount
