# pypcaptools介绍

pypcaptools 是一个用于处理pcap文件的 Python 库，可以实现以下功能：
1. 将流量按照session进行分隔，可以输出pcap格式或json格式。
2. 将pcap文件导入到mysql数据库中
3. 从mysql数据库中读取流量数据，并进行统计

## 安装

```bash
pip install pypcaptools
```

## Quick Start

1. 分流
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

2. 将流量分流并加入到mysql数据库中
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

3. 统计入库的流量信息
```python
from pypcaptools import TrafficInfo
db_config = {
    "host": "",
    "port": 3306,
    "user": "root",
    "password": "password",
    "database": "traffic",
    "table": "table",
}

traffic_info = TrafficInfo(db_config)
traffic_info.use_table("table_name")      # 这里要指定统计的table
transformed_data = traffic_info.table_columns   # 获得该table的表头和对应注释信息

traffic_num = traffic_info.count_flows("packet_length > 10 and accessed_website == 163.com")  # 获得满足条件的流的个数
website_list = traffic_info.get_value_list_unique("accessed_website")    # 获得table中的网站列表
website_list = traffic_info.get_payload("packet_length > 10")    # 获得满足特定条件的流的payload序列
```
