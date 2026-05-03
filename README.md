# pypcaptools

`pypcaptools` 是一个用于解析 `pcap` 文件中 TCP 流量，并将 trace、flow、resource 级特征写入 MySQL 的 Python 库。它主要面向网络流量指纹分析、网站访问流量分析和机器学习特征提取场景。

这个库可以按两种方式使用：

- 在本地直接解析 `pcap` 文件，读取 trace 和 flow 序列。
- 将 `pcap` 文件，以及可选的资源元数据 JSON 文件，导入规范化的 MySQL 表结构。

## 功能特性

- 基于 `dpkt` 的轻量级 `pcap` 解析。
- 提取 trace 级包序列：时间戳、payload 大小、方向、包数量和捕获时间。
- 按 TCP 五元组聚合 flow，并保留每条 flow 的包序列和 trace 包索引。
- 支持从外部 JSON 元数据映射 resource 级信息，例如 HTTP/2 解码器输出。
- MySQL 表结构采用 `Trace -> Flow -> Resource` 三层关系。
- flow 和 resource 数据支持批量写入。
- 提供 trace、flow、resource 的查询辅助接口，便于后续特征提取。

## 环境要求

- Python 3.8+
- 使用数据库导入和查询接口时，需要 MySQL 8.0+
- 当前支持的链路层格式：Ethernet、Linux cooked capture v1
- 当前解析范围：IPv4 上的 TCP 流量

## 安装

```bash
pip install pypcaptools
```

安装指定版本：

```bash
pip install pypcaptools==2.6
```

从源码进行本地开发：

```bash
pip install -e .
```

## 快速开始

不连接数据库，直接解析一个 `pcap` 文件：

```python
from pypcaptools import PcapHandler

handler = PcapHandler("captures/example.pcap")

trace = handler.get_trace_sequence()
flows = handler.get_flow_sequences()

print(trace["total_packet_count"])
print(len(flows))

for flow_key, flow in flows.items():
    print(flow_key, flow["source_ip"], flow["destination_ip"], len(flow["payload_seq"]))
```

将 `pcap` 文件导入 MySQL：

```python
from pypcaptools import PcapToDatabaseHandler, initialize_database_schema

db_config = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "your_password",
    "database": "traffic",
}

base_table_name = "direct_traffic"

initialize_database_schema(db_config, base_table_name)

handler = PcapToDatabaseHandler(
    db_config=db_config,
    base_table_name=base_table_name,
    input_pcap_file="captures/example.pcap",
    input_json_file="captures/example.json",
    protocol="HTTPS",
    accessed_website="example.com",
    site_id="example",
    collection_machine="local-dev",
)

if not handler.pcap_to_database():
    raise RuntimeError("PCAP 数据导入失败")
```

如果只有 `pcap` 文件，可以省略 `input_json_file`。导入器仍会创建 trace 和 flow 记录，并跳过 resource 记录。

## 数据库表结构

`initialize_database_schema(db_config, base_table_name)` 会创建三张关联表：

- `{base_table_name}_trace`：每个捕获文件对应一条记录。
- `{base_table_name}_flow`：每条 TCP flow 对应一条记录，通过 `trace_id` 关联 trace。
- `{base_table_name}_resource`：每个应用层资源对应一条记录，通过 `flow_id` 关联 flow。

主要序列字段以 MySQL JSON 类型存储：

- `timestamps_seq`：相对于 trace 或 flow 起始时间的包时间戳。
- `payload_seq`：TCP payload 大小序列。
- `direction_seq`：包方向，`1` 表示出站，`-1` 表示入站。
- `trace_packet_indices`：当前 flow 或 resource 涉及的 trace 级 TCP-only 包索引。

## Resource 级特征

当 `input_json_file` 来自兼容解码器，例如 `traffic2db.http2decoder` 时，resource 表可以保留 HTTP 资源到 TCP 包号的映射：

- `headers_packet_num`：请求 headers 所在的 TCP-only 包号。
- `request_packet_nums`：请求相关的 TCP-only 包号列表。
- `response_packet_nums`：响应相关的 TCP-only 包号列表。
- `headers_flow_packet_num`：请求 headers 所在的 flow 内包号。
- `request_flow_packet_nums`：请求相关的 flow 内包号列表。
- `response_flow_packet_nums`：响应相关的 flow 内包号列表。
- `trace_packet_indices`：请求和响应相关包号的合集。
- `request_start_ts`、`response_start_ts`、`response_end_ts`：资源请求和响应时间。
- `request_size_bytes`、`resource_size_bytes`：请求体和响应体大小。
- `request_packet_count`、`server_packet_count`：请求包数和响应包数。
- `ttfb_ms`、`duration_ms`：首包延迟和资源总时长。

这些字段可以和 flow 表中的 `timestamps_seq`、`payload_seq`、`direction_seq`、`trace_packet_indices` 联合使用，用于构建 packet size、burst、时序和累计流量曲线等特征。

## 查询示例

读取 flow 的 payload 序列：

```python
from pypcaptools.TrafficInfo import FlowInfo

flow_info = FlowInfo(db_config)
flow_info.use_table("direct_traffic")

payload_sequences = flow_info.get_payload_sequence("transport_protocol == 'TCP'")
```

读取 resource 记录，并同时 join 对应的 flow 和 trace 特征字段：

```python
from pypcaptools.TrafficInfo import ResourceInfo

resource_info = ResourceInfo(db_config)
resource_info.use_table("direct_traffic")

rows = resource_info.get_feature_inputs("http_status == 200")
```

条件语法支持简单的 Python 风格比较，例如 `field == value`、`field != value` 和 `field > value`。如果需要复杂过滤，建议直接使用底层数据库类执行 SQL。

## 示例脚本

`examples/` 目录下提供了可以直接运行的示例：

- `examples/inspect_pcap.py`：查看 `pcap` 文件中的 trace 和 flow 序列。
- `examples/pcap_to_database.py`：将 `pcap` 和可选 JSON 元数据导入 MySQL。
- `examples/flow_to_database.py`：只导入 `pcap`，存储 trace 和 flow，不写入 resource。
- `examples/flow_info.py`：查询已入库的 flow 数据。
- `examples/trace_info.py`：查询已入库的 trace 数据。
- `examples/resource_info.py`：查询 resource，并同时读取对应的 flow 和 trace 特征。

## 开发说明

本项目使用 `src/` 目录布局。本地开发时建议使用 editable 安装：

```bash
pip install -e .
```

发布或提交代码前，至少运行：

```bash
python -m compileall -q src examples
python -m build
```

## 许可证

本项目基于 [MIT License](LICENSE) 开源。
