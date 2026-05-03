"""在没有 resource 元数据的情况下，将 pcap 文件导入 MySQL。

该脚本只写入 trace 和 flow 记录，适用于没有兼容 JSON 文件进行
resource 级映射的场景。

示例：
    python examples/flow_to_database.py \
        --pcap captures/example.pcap \
        --base-table direct_traffic \
        --website example.com
"""

import argparse
import os

from pypcaptools import PcapToDatabaseHandler, initialize_database_schema


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="导入 pcap 中的 trace 和 flow 记录。")
    parser.add_argument("--pcap", required=True, help="输入 pcap 文件路径。")
    parser.add_argument(
        "--base-table",
        default="direct_traffic",
        help="基础表名。导入器会创建 *_trace、*_flow 和 *_resource 表。",
    )
    parser.add_argument("--website", default="unknown", help="访问网站标签。")
    parser.add_argument("--site-id", default=None, help="稳定的站点标识。")
    parser.add_argument("--protocol", default="HTTPS", help="流量协议标签。")
    parser.add_argument(
        "--collection-machine",
        default="",
        help="采集该 pcap 的机器名称。",
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

    if not initialize_database_schema(db_config, args.base_table):
        raise SystemExit("数据库表结构初始化失败。")

    handler = PcapToDatabaseHandler(
        db_config=db_config,
        base_table_name=args.base_table,
        input_pcap_file=args.pcap,
        protocol=args.protocol,
        accessed_website=args.website,
        site_id=args.site_id,
        collection_machine=args.collection_machine,
    )

    if not handler.pcap_to_database():
        raise SystemExit("PCAP 数据导入失败。")

    print("Trace 和 flow 导入完成。")


if __name__ == "__main__":
    main()
