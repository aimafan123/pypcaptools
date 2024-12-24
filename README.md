# pypcaptools介绍

![PyPI version](https://img.shields.io/pypi/v/pypcaptools.svg)


pypcaptools 是一个功能强大的 Python 库，用于处理 pcap 文件，支持多种流量分析和处理场景。

## 核心功能

1. 流量分隔

按照会话 (Session) 分隔流量，并支持以 pcap 或 json 格式输出。

2. 导入 MySQL 数据库
   
将流量数据从 pcap 文件导入到 MySQL 数据库中，方便后续管理和分析。可以选择以flow为单位进行导入，也可以选择以一个pcap文件为一个trace的单位进行导入

3. 流量统计
   
从 MySQL 数据库中读取流量数据，进行灵活的条件查询和统计。

> mysql数据库的表结构参考
> 1. [单纯存储flow](docs/sql/flow.sql)
> 2. [存储trace](docs/sql/trace.sql)
> 3. [与trace关联的flow](docs/sql/flowintrace.sql)

## 安装
可以通过 pip 安装 `pypcaptools`

```bash
pip install pypcaptools
```

## Quick Start

### 1. 流量分隔


```python
from pypcaptools import PcapHandler

origin_pcap = "/path/dir/filename"

ph = PcapHandler(origin_pcap)
output_dir = "/path/dir/output_dir"

# 分流之后以pcap格式输出，TCP流允许从中途开始（即没有握手过程）
session_num, output_path = ph.split_flow(output_dir, tcp_from_first_packet=False, output_type="pcap")

# 分流之后以json格式输出，输出一个json文件，其中每一个单元表示一条流，TCP流必须从握手阶段开始，从中途开始的TCP流会被丢弃
session_num, output_path = ph.split_flow(output_dir, tcp_from_first_packet=True, output_type="json")
```

### 2. 以flow为单位加入到mysql数据库中

```python
from pypcaptools import PcapToDatabaseHandler
db_config = {
    "host": "",
    "port": 3306,
    "user": "root",
    "password": "password",
    "database": "traffic",
    "table": "table",
}

# 参数依次为 处理的pcap路径、mysql配置、应用层协议类型、访问网站/行为、采集机器、table注释
handler = PcapToDatabaseHandler(
    "test.pcap", db_config, "https", "github.com", "vultr10", "测试用数据集"
)
handler.split_flow_to_database()
```

### 3. 以pcap（trace）为单位加入到mysql数据库中

```python
from pypcaptools import PcapToDatabaseHandler

db_config = {
    "host": "",
    "port": 3306,
    "user": "root",
    "password": "password",
    "database": "traffic",
    "table": "table",
}

# 参数依次为 处理的pcap路径、mysql配置、应用层协议类型、访问网站/行为、采集机器、table注释
handler = PcapToDatabaseHandler(
    "test.pcap", db_config, "https", "github.com", "vultr10", "测试用数据集"
)
handler.pcap_to_database()  # 注意，会生成两个table，分别是table_trace和table_flow，前者存储trace的总体信息和序列字段，后者存储该trace中每个flow的信息和序列字段，两个库通过trace_id关联
```

### 4. 流量统计（Flow）

```python
from pypcaptools.TrafficInfo import FlowInfo
db_config = {
    "host": "",
    "port": 3306,
    "user": "root",
    "password": "password",
    "database": "traffic",
    "table": "table",
}

traffic_info = FlowInfo(db_config)
traffic_info.use_table("table_name")      # 这里要指定统计的table
transformed_data = traffic_info.table_columns   # 获得该table的表头和对应注释信息

traffic_num = traffic_info.count_flows("packet_length > 10 and accessed_website == 163.com")  # 获得满足条件的流的个数
website_list = traffic_info.get_value_list_unique("accessed_website")    # 获得table中的网站列表
website_list = traffic_info.get_payload("packet_length > 10")    # 获得满足特定条件的流的payload序列
```

### 5. 流量统计（Trace）
```python
from pypcaptools.TrafficInfo import TraceInfo
db_config = {
    "host": "",
    "port": 3306,
    "user": "root",
    "password": "password",
    "database": "traffic",
    "table": "table",
}

traffic_info = TraceInfo(db_config)
traffic_info.use_table("table_name")      # 这里要指定统计的table
transformed_data = traffic_info.table_columns   # 获得该table的表头和对应注释信息

traffic_num = traffic_info.count_flows("packet_length > 10 and accessed_website == 163.com")  # 获得满足条件的流的个数
website_list = traffic_info.get_value_list_unique("accessed_website")    # 获得table中的网站列表
website_list = traffic_info.get_payload("packet_length > 10")    # 获得满足特定条件的流的payload序列
```

## 贡献指南

如果你对 `pypcaptools` 感兴趣，并希望为项目贡献代码或功能，欢迎提交 Issue 或 Pull Request！

## 许可证

本项目基于 [MIT License](LICENSE) 许可协议开源。
