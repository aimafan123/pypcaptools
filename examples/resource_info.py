"""查询 resource 记录，并 join 对应的 flow 和 trace 特征输入。

示例：
    python examples/resource_info.py --base-table direct_traffic \
        --condition "http_status == 200"
"""

import argparse
import os

from pypcaptools.TrafficInfo import ResourceInfo


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="查询已入库的 resource 特征。")
    parser.add_argument(
        "--base-table",
        default="direct_traffic",
        help="导入数据时使用的基础表名。",
    )
    parser.add_argument(
        "--condition",
        default="1 == 1",
        help="简单的 Python 风格过滤条件，例如：http_status == 200。",
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

    resource_info = ResourceInfo(db_config)
    resource_info.use_table(args.base_table)

    rows = resource_info.get_feature_inputs(args.condition)
    print(f"resource 数量: {len(rows)}")

    if rows:
        first = rows[0]
        print(f"第一条 resource ID: {first['resource_id']}")
        print(f"第一条 URL: {first['url']}")
        print(f"第一条 flow payload 包数量: {len(first['flow_payload_seq'])}")


if __name__ == "__main__":
    main()
