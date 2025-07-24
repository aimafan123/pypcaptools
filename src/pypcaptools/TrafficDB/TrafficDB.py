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

    def get_table_columns(self, table_name):
        if self.cursor is None or self.conn is None:
            raise RuntimeError("数据库连接未建立，cursor 或 conn 为 None。")
        query = f"SHOW FULL COLUMNS FROM {table_name}"
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
        if self.cursor is None or self.conn is None:
            raise RuntimeError("数据库连接未建立，cursor 或 conn 为 None。")
        if value:
            self.cursor.execute(sql, value)
        else:
            self.cursor.execute(sql)

        values = self.cursor.fetchall()

        return [value[0] for value in values]

    def create_database(self):
        if self.cursor is None or self.conn is None:
            raise RuntimeError("数据库连接未建立，cursor 或 conn 为 None。")
        self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
        self.cursor.execute(f"USE {self.database}")

    def create_table(self):
        pass

    def close(self):
        if self.conn:
            self.conn.close()

    def add_traffic(self, traffic_dic):
        pass

    def __del__(self):
        self.close()
