import mysql.connector

from pypcaptools.TrafficDB.TrafficDB import TrafficDB


class TraceDB(TrafficDB):
    def __init__(self, host, port, user, password, database, table, comment=""):
        super().__init__(host, port, user, password, database, table, comment)

    def create_table(self):
        create_trace_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.table+'_trace'} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            entry_time DATETIME NOT NULL COMMENT '入库时间',
            capture_time DATETIME COMMENT '采集时间',
            timestamp MEDIUMBLOB COMMENT '时间戳（绝对）',
            payload MEDIUMBLOB NOT NULL COMMENT 'payload长度+方向',
            protocol VARCHAR(30) COMMENT '协议（HTTPs、Vmess、Tor、Obfs4等）',
            transport_protocol ENUM('TCP', 'UDP') COMMENT '传输层协议',
            accessed_website VARCHAR(255) COMMENT '访问网站域名/应用',
            flownum INT UNSIGNED COMMENT '这个trace中包含的流数量',
            packet_length INT UNSIGNED COMMENT '包长度',
            packet_length_no_payload INT UNSIGNED COMMENT '去除payload为0的包长度',
            collection_machine VARCHAR(255) COMMENT '采集机器',
            pcap_path VARCHAR(255) COMMENT '原始pcap路径',
            UNIQUE (accessed_website, capture_time, protocol)
        );
        """
        self.cursor.execute(create_trace_table_sql)
        self.conn.commit()
        create_flow_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.table+'_flow'} (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            trace_id BIGINT NOT NULL COMMENT '关联trace表的ID',
            entry_time DATETIME NOT NULL COMMENT '入库时间',
            capture_time DATETIME COMMENT '采集时间',
            source_ip VARCHAR(45) NOT NULL COMMENT '源IP地址',
            destination_ip VARCHAR(45) NOT NULL COMMENT '目的IP地址',
            source_port SMALLINT UNSIGNED NOT NULL COMMENT '源端口',
            destination_port SMALLINT UNSIGNED NOT NULL COMMENT '目的端口',
            timestamp MEDIUMBLOB COMMENT '时间戳（相比于trace的开头）',
            payload MEDIUMBLOB NOT NULL COMMENT 'payload长度+方向',
            protocol VARCHAR(30) COMMENT '协议（HTTPs、Vmess、Tor、Obfs4等）',
            transport_protocol ENUM('TCP', 'UDP') COMMENT '传输层协议',
            accessed_website VARCHAR(255) COMMENT '访问网站域名/应用',
            packet_length INT UNSIGNED COMMENT '包长度',
            packet_length_no_payload INT UNSIGNED COMMENT '去除payload为0的包长度',
            collection_machine VARCHAR(255) COMMENT '采集机器',
            pcap_path VARCHAR(255) COMMENT '原始pcap路径',
            FOREIGN KEY (trace_id) REFERENCES {self.table+'_trace'}(id) ON DELETE CASCADE,
            UNIQUE (source_ip, destination_ip, source_port, destination_port, protocol, capture_time)
        );
        """
        self.cursor.execute(create_flow_table_sql)
        self.conn.commit()

    def add_trace(self, traffic_dic):
        # 构建插入语句
        # + 记录首次发现时间
        columns = ", ".join(traffic_dic.keys())
        placeholders = ", ".join(["%s"] * len(traffic_dic))
        insert_sql = f"""
        INSERT IGNORE INTO {self.table+'_trace'} ({columns})
        VALUES ({placeholders});
        """
        values = tuple(traffic_dic.values())
        self.cursor.execute(insert_sql, values)
        self.conn.commit()

        # 获得id的值，为flow表的插入做准备
        self.cursor.execute("SELECT LAST_INSERT_ID();")
        inserted_id = self.cursor.fetchone()[0]

        return inserted_id

    def add_traffic(self, traffic_dic):
        # 构建插入语句
        # + 记录首次发现时间
        columns = ", ".join(traffic_dic.keys())
        placeholders = ", ".join(["%s"] * len(traffic_dic))
        insert_sql = f"""
        INSERT IGNORE INTO {self.table+'_flow'} ({columns})
        VALUES ({placeholders});
        """
        values = tuple(traffic_dic.values())
        self.cursor.execute(insert_sql, values)
        self.conn.commit()
