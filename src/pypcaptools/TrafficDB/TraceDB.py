import json
from typing import Optional, Tuple

import mysql.connector

from pypcaptools.TrafficDB.TrafficDB import TrafficDB


class TraceDB(TrafficDB):
    """
    管理 'traces' 数据表，用于存储完整的网页访问记录。
    """

    def __init__(
        self,
        host,
        port,
        user,
        password,
        database,
        table="traces",
        comment="存储每一次完整的网页访问记录 (Trace)",
    ):
        super().__init__(host, port, user, password, database, table, comment)

    def create_table(self):
        """
        使用指定的现代化表结构创建 'traces' 表。
        """
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS `{self.table}` (
          `id` bigint NOT NULL AUTO_INCREMENT,
          `accessed_website` varchar(255) NOT NULL,
          `capture_time` datetime NOT NULL,
          `timestamps_seq` JSON,
          `payload_seq` JSON NOT NULL,
          `direction_seq` JSON NOT NULL,
          `protocol` varchar(30) DEFAULT 'HTTPS',
          `collection_machine` varchar(255) DEFAULT NULL,
          `pcap_path` varchar(255) NOT NULL,
          `json_path` varchar(255) NOT NULL,
          `flow_count` int unsigned DEFAULT NULL,
          `total_packet_count` int unsigned DEFAULT NULL,
          `metadata` json DEFAULT NULL,
          `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (`id`),
          UNIQUE KEY `uk_website_capture_time` (`accessed_website`,`capture_time`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='{self.comment}';
        """
        print(f"正在为 '{self.table}' 执行建表操作...")
        self.execute_commit(create_table_sql)
        print("数据表创建成功 (如果它尚不存在)。")

    def add_trace(self, trace_data: dict) -> int:
        """
        插入一条完整的 trace 记录，并将 Python 对象序列化为 JSON。

        Args:
            trace_data (dict): 包含 trace 数据的字典，键名需与列名匹配。

        Returns:
            int: 新插入行的 ID。如果行未被插入，则返回 0。
        """
        data_to_insert = trace_data.copy()
        json_fields = ["timestamps_seq", "payload_seq", "direction_seq", "metadata"]
        for field in json_fields:
            if field in data_to_insert and data_to_insert[field] is not None:
                if not isinstance(data_to_insert[field], str):
                    data_to_insert[field] = json.dumps(data_to_insert[field])

        columns = ", ".join(f"`{k}`" for k in data_to_insert.keys())
        placeholders = ", ".join(["%s"] * len(data_to_insert))

        insert_sql = (
            f"INSERT IGNORE INTO `{self.table}` ({columns}) VALUES ({placeholders})"
        )
        values = tuple(data_to_insert.values())

        rows_affected = self.execute_commit(insert_sql, values)

        if rows_affected > 0:
            # 如果确实插入了新行，则获取其 ID
            result = self.query("SELECT LAST_INSERT_ID() AS id")
            return result[0]["id"] if result else 0

        return 0


if __name__ == "__main__":
    db_config = {
        "host": "localhost",
        "port": 3306,
        "user": "root",
        "password": "aimafan",
        "database": "traffic_test",
    }

    example_trace = {
        "accessed_website": "google.com",
        "capture_time": "2025-08-28 15:50:00",
        "timestamps_seq": [0.01, 0.02, 0.15],
        "payload_seq": [512, 1024, 512],
        "direction_seq": [1, -1, 1],
        "pcap_path": "/data/pcaps/google.com_20250828155000.pcap",
        "json_path": "/data/json/google.com_20250828155000.json",
        "total_packet_count": 3,
    }

    # 使用 'with' 语句自动管理数据库连接的建立和关闭
    try:
        with TraceDB(**db_config) as db:
            # 首次运行时需要初始化数据库
            db.setup_database()

            # 创建数据表（如果不存在）
            db.create_table()

            # 插入一条新的 trace 记录
            inserted_id = db.add_trace(example_trace)

            if inserted_id > 0:
                print(f"✅ 成功插入一条 Trace 记录，ID: {inserted_id}")
            else:
                print("⚠️ 记录已存在或插入失败，没有新行被插入。")

    except mysql.connector.Error as err:
        print(f"数据库操作出错: {err}")
