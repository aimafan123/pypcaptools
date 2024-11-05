# pypcaptools介绍

pypcaptools 是一个用于处理pcap文件的 Python 库，可以实现以下功能：
1. 将流量按照session进行分隔，可以输出pcap格式或json格式。

## 安装

```bash
pip install pypcaptools
```

## Quick Start

```python
from pypcaptools import PcapHandler

origin_pcap = "/path/dir/filename"

ph = PcapHandler(origin_pcap)
output_dir = "/path/dir/output_dir"

# 分流之后以pcap格式输出，TCP流允许从中途开始（即没有握手过程）
ph.split_flow(output_dir, tcp_from_first_packet=False, output_type="pcap")

# 分流之后以json格式输出，输出一个json文件，其中每一个单元表示一条流，TCP流必须从握手阶段开始，从中途开始的TCP流会被丢弃
ph.split_flow(output_dir, tcp_from_first_packet=True, output_type="json")
```