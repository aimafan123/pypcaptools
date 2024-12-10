import mysql.connector


class TrafficDB:
    def __init__(self, host, port, user, password, database, table, comment=""):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.port = int(port)
        self.table = table
        self.conn = None
        self.cursor = None
        self.comment = comment

    def connect(self):
        try:
            self.conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                port=self.port,
                connection_timeout=300,
            )
            self.cursor = self.conn.cursor()
            self.create_database()
            self.create_table()
        except mysql.connector.Error as error:
            raise mysql.connector.Error(f"Error connecting to MySQL database: {error}")

    def get_table_columns(self):
        query = f"SHOW FULL COLUMNS FROM {self.table}"
        self.cursor.execute(query)
        columns_info = self.cursor.fetchall()
        # 格式化结果
        column_details = []
        for column in columns_info:
            column_details.append(
                {
                    "Field": column[0],
                    "Type": column[1],
                    "Collation": column[2],
                    "Null": column[3],
                    "Key": column[4],
                    "Default": column[5],
                    "Extra": column[6],
                    "Comment": column[8],
                }
            )
        return column_details

    def execute(self, sql, value=None):
        """
        执行sql语句
        """
        if value:
            self.cursor.execute(sql, value)
        else:
            self.cursor.execute(sql)

        values = self.cursor.fetchall()

        return [value[0] for value in values]

    def create_database(self):
        self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
        self.cursor.execute(f"USE {self.database}")

    def create_table(self):
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
            packet_length INT UNSIGNED COMMENT '包长度',
            packet_length_no_payload INT UNSIGNED COMMENT '去除payload为0的包长度',
            collection_machine VARCHAR(255) COMMENT '采集机器',
            pcap_path VARCHAR(255) COMMENT '原始pcap路径',
            UNIQUE (source_ip, destination_ip, source_port, destination_port, pcap_path, protocol, capture_time)
        ) COMMENT = '{self.comment}';
        """
        self.cursor.execute(create_table_sql)
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

    def add_traffic(self, traffic_dic):
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

    def __del__(self):
        self.close()
