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
可以参考 `examples` 目录中的示例代码，快速了解并使用本库的功能。

## 贡献指南

如果你对 `pypcaptools` 感兴趣，并希望为项目贡献代码或功能，欢迎提交 Issue 或 Pull Request！

## 许可证

本项目基于 [MIT License](LICENSE) 许可协议开源。
