# pypcaptools

`pypcaptools` 是一个为现代网络流量指纹分析而设计的强大 Python 库。它能够高效解析 `pcap` 文件，并支持将流量数据与应用层资源信息（来自关联的 `json` 文件）相结合，最终将结构化的数据存入 MySQL 数据库。

## 核心功能 🚀

1.  **现代化数据库架构**

      * 采用 **Trace → Flow → Resource** 三层关联的表结构，精准地描述了“一次完整的访问”、“访问中的网络流”以及“网络流中加载的应用资源”之间的层次关系。
      * 使用 `JSON` 数据类型存储时间戳、数据包大小和方向序列，既节省空间又便于机器学习模型直接调用。

2.  **关联数据处理**

      * 突破了传统仅分析 `pcap` 文件的局限，能够**协同处理 `pcap` 文件和其关联的 `json` 文件**（例如，通过浏览器插件或 `mitmproxy` 导出的资源加载日志）。
      * 这使得将底层的网络流数据与高层的应用资源（如 URL、HTTP 状态码、Content-Type）进行精确映射成为可能，极大地丰富了数据维度。

3.  **高效与稳健**

      * 核心解析引擎从 `scapy` 全面切换到更轻量、更高性能的 **`dpkt`**，大幅提升了处理大型 `pcap` 文件时的速度和内存效率。
      * 数据库操作采用**上下文管理器**（`with` 语句）和**批量插入**（`executemany`），确保了数据库连接的安全、自动关闭以及卓越的数据写入性能。

## 数据库设计 📊

新版 `pypcaptools` 围绕一个基础名称（`base_table_name`）动态创建三张关联表，以存储层次化的流量数据。

  * **`{base_name}_trace` 表**: 存储一次完整的捕获记录（对应一个 `pcap` 文件）。它包含了该次访问的总体元数据和整合后的数据包序列。
  * **`{base_name}_flow` 表**: 存储 `trace` 中的单个网络流（由五元组定义）。通过外键 `trace_id` 与 `trace` 表关联。
  * **`{base_name}_resource` 表**: 存储 `flow` 中加载的具体应用层资源（如一个 GET 请求的 URL 和响应）。通过外键 `flow_id` 与 `flow` 表关联，其数据主要来源于辅助的 `json` 文件。

这种设计极大地增强了数据的可分析性，为复杂的流量指纹研究和模型训练提供了坚实的基础。

## 安装

可以通过 pip 安装 `pypcaptools`:

```bash

pip install pypcaptools==2.1
```

## 快速开始 ⚡

下面的示例展示了如何使用 `PcapToDatabaseHandler` 将一个 `pcap` 文件和其关联的 `json` 资源文件一同导入数据库。

```python
from pypcaptools import PcapToDatabaseHandler, initialize_database_schema

# 1. 配置数据库连接
db_config = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "your_password",
    "database": "your_traffic_db",
}

# 2. (可选，首次运行时执行) 初始化数据库和表结构
# 这个函数会确保数据库和三张关联表都已创建。
base_name = "direct_traffic"
initialize_database_schema(db_config, base_table_name=base_name)

# 3. 初始化处理器
# 它将连接到已创建的 direct_traffic_trace, direct_traffic_flow, 
# 和 direct_traffic_resource 这三张表。
handler = PcapToDatabaseHandler(
    db_config=db_config,
    base_table_name=base_name, 
    input_pcap_file="captures/google.com.pcap",
    input_json_file="captures/google.com.json",
    protocol="HTTPS",
    accessed_website="google.com",
    collection_machine="local-dev-machine"
)

# 4. 执行处理和入库操作
# 该方法会完成所有解析、关联和数据库批量插入工作。
success = handler.pcap_to_database()

if success:
    print("✅ 成功将 PCAP 和 JSON 数据导入数据库。")
else:
    print("❌ 导入数据失败，请检查日志。")

```

## 贡献指南

如果你对 `pypcaptools` 感兴趣，并希望为项目贡献代码或功能，欢迎提交 Issue 或 Pull Request！

## 许可证

本项目基于 [MIT License](https://www.google.com/search?q=LICENSE) 许可协议开源。