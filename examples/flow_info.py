"""查询已导入数据库的 flow 记录。

示例：
    python examples/flow_info.py --base-table direct_traffic \
        --condition "transport_protocol == 'TCP'"
"""

import argparse
import os

from pypcaptools.TrafficInfo import FlowInfo


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="查询已入库的 flow 特征。")
    parser.add_argument(
        "--base-table",
        default="direct_traffic",
        help="导入数据时使用的基础表名。",
    )
    parser.add_argument(
        "--condition",
        default="1 == 1",
        help="简单的 Python 风格过滤条件，例如：transport_protocol == 'TCP'。",
    )
    parser.add_argument("--host", default=os.getenv("MYSQL_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MYSQL_PORT", "3306")))
    parser.add_argument("--user", default=os.getenv("MYSQL_USER", "root"))
    parser.add_argument("--password", default=os.getenv("MYSQL_PASSWORD", ""))
    parser.add_argument("--database", default=os.getenv("MYSQL_DATABASE", "traffic"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    db_config = {
        "host": args.host,
        "port": args.port,
        "user": args.user,
        "password": args.password,
        "database": args.database,
    }

    flow_info = FlowInfo(db_config)
    flow_info.use_table(args.base_table)

    count = flow_info.count_flows(args.condition)
    payload_sequences = flow_info.get_payload_sequence(args.condition)
    source_ips = flow_info.get_value_list_unique("source_ip", args.condition)

    print(f"flow 数量: {count}")
    print(f"前 10 个唯一源 IP: {source_ips[:10]}")
    print(f"payload 序列数量: {len(payload_sequences)}")

    if payload_sequences:
        print(f"第一条 payload 序列长度: {len(payload_sequences[0])}")


if __name__ == "__main__":
    main()
