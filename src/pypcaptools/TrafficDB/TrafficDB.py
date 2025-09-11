import mysql.connector


class TrafficDB:
    """
    一个使用上下文管理器来处理 MySQL 数据库连接的基类。
    """

    def __init__(self, host, port, user, password, database, table, comment=""):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.database = database
        self.table = table
        self.comment = comment
        self.conn = None
        self.cursor = None

    def connect(self):
        """(新增) 显式建立数据库连接的方法"""
        try:
            self.conn = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
            )
            self.cursor = self.conn.cursor(dictionary=True)
            return self
        except mysql.connector.Error as err:
            if err.errno == mysql.connector.errorcode.ER_BAD_DB_ERROR:
                self.conn = mysql.connector.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                )
                self.cursor = self.conn.cursor(dictionary=True)
                print(
                    f"数据库 '{self.database}' 不存在。您可能需要运行 setup_database() 方法进行初始化。"
                )
                return self
            else:
                raise

    def close(self):
        """(新增) 显式关闭数据库连接的方法"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def __enter__(self):
        """
        进入 'with' 语句的运行时上下文。
        负责建立数据库连接。
        """
        try:
            self.conn = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,  # 直接连接到指定的数据库
            )
            # 使用字典游标，让查询结果更易读
            self.cursor = self.conn.cursor(dictionary=True)
            return self
        except mysql.connector.Error as err:
            # 如果错误是“数据库不存在”
            if err.errno == mysql.connector.errorcode.ER_BAD_DB_ERROR:
                # 连接时不指定数据库，以便后续创建它
                self.conn = mysql.connector.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                )
                self.cursor = self.conn.cursor(dictionary=True)
                print(
                    f"数据库 '{self.database}' 不存在。您可能需要运行 setup_database() 方法进行初始化。"
                )
                return self
            else:
                # 其他类型的错误则直接抛出
                raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        退出运行时上下文。
        确保游标和连接被安全关闭。
        """
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def setup_database(self):
        """
        如果数据库不存在，则创建它，并切换到该数据库。
        这是一个一次性的设置操作。
        """
        print(f"正在为 '{self.database}' 执行数据库初始化...")
        if self.cursor is None:
            raise RuntimeError("游标不可用，数据库连接可能已失败。")
        self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
        self.cursor.execute(f"USE {self.database}")
        print("数据库初始化完成。")

    def query(self, sql: str, params: tuple = None) -> list:
        """
        执行 SELECT 查询并获取所有结果。

        Args:
            sql (str): SQL 查询语句。
            params (tuple, optional): 绑定到查询中的参数。默认为 None。

        Returns:
            list: 一个由字典组成的列表，每个字典代表一行数据。
        """
        if self.cursor is None:
            raise RuntimeError("数据库连接未建立。")
        self.cursor.execute(sql, params or ())
        return self.cursor.fetchall()

    def execute_commit(self, sql: str, params: tuple = None) -> int:
        """
        执行数据修改语句 (INSERT, UPDATE, DELETE) 并提交事务。

        Args:
            sql (str): SQL 语句。
            params (tuple, optional): 绑定到语句中的参数。默认为 None。

        Returns:
            int: 受该语句影响的行数。
        """
        if self.cursor is None or self.conn is None:
            raise RuntimeError("数据库连接未建立。")
        self.cursor.execute(sql, params or ())
        self.conn.commit()
        return self.cursor.rowcount

    def create_table(self):
        """
        创建数据表的占位方法。子类必须实现此方法。
        """
        raise NotImplementedError("子类必须实现 create_table 方法。")
