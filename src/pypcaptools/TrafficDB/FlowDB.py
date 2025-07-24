import mysql.connector

from pypcaptools.TrafficDB.TrafficDB import TrafficDB


class FlowDB(TrafficDB):
    def __init__(self, host, port, user, password, database, table, comment=""):
        super().__init__(host, port, user, password, database, table, comment)

    def create_table(self):
        if self.cursor is None or self.conn is None:
            raise RuntimeError("数据库连接未建立，cursor 或 conn 为 None。")
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.table} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            entry_time DATETIME NOT NULL COMMENT '入库时间',
            capture_time DATETIME COMMENT '采集时间',
            source_ip VARCHAR(45) NOT NULL COMMENT '源IP地址',
            destination_ip VARCHAR(45) NOT NULL COMMENT '目的IP地址',
            source_port SMALLINT UNSIGNED NOT NULL COMMENT '源端口',
            destination_port SMALLINT UNSIGNED NOT NULL COMMENT '目的端口',
            timestamp MEDIUMBLOB COMMENT '时间戳（绝对）',
            payload MEDIUMBLOB NOT NULL COMMENT 'payload长度+方向',
            protocol VARCHAR(30) COMMENT '协议（HTTPs、Vmess、Tor、Obfs4等）',
            transport_protocol ENUM('TCP', 'UDP') COMMENT '传输层协议',
            accessed_website VARCHAR(255) COMMENT '访问网站域名/应用',
            sni VARCHAR(255) DEFAULT NULL COMMENT 'TLS握手中提供的SNI（Server Name Indication）',
            packet_length INT UNSIGNED COMMENT '包长度',
            packet_length_no_payload INT UNSIGNED COMMENT '去除payload为0的包长度',
            collection_machine VARCHAR(255) COMMENT '采集机器',
            pcap_path VARCHAR(255) COMMENT '原始pcap路径',
            UNIQUE (source_ip, destination_ip, source_port, destination_port, pcap_path, protocol, capture_time)
        ) COMMENT = '{self.comment}';
        """
        self.cursor.execute(create_table_sql)
        self.conn.commit()

    def add_traffic(self, traffic_dic):
        if self.cursor is None or self.conn is None:
            raise RuntimeError("数据库连接未建立，cursor 或 conn 为 None。")
        # 构建插入语句
        # + 记录首次发现时间
        columns = ", ".join(traffic_dic.keys())
        placeholders = ", ".join(["%s"] * len(traffic_dic))
        insert_sql = f"""
        INSERT IGNORE INTO {self.table} ({columns})
        VALUES ({placeholders});
        """
        values = tuple(traffic_dic.values())
        self.cursor.execute(insert_sql, values)
        self.conn.commit()
