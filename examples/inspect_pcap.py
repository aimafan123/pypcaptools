"""查看 pcap 文件中的 trace 和 flow 序列。

示例：
    python examples/inspect_pcap.py captures/example.pcap --limit 10
"""

import argparse

from pypcaptools import PcapHandler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="查看解析后的 pcap flow 序列。")
    parser.add_argument("pcap", help="输入 pcap 文件路径。")
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="最多输出的 flow 数量。",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    handler = PcapHandler(args.pcap)

    trace = handler.get_trace_sequence()
    flows = handler.get_flow_sequences()

    print(f"包数量: {trace['total_packet_count']}")
    print(f"flow 数量: {len(flows)}")
    print(f"捕获时间: {trace['capture_time']}")
    print(f"本地 IP: {handler.local_ip or 'unknown'}")

    for index, (flow_key, flow) in enumerate(flows.items(), start=1):
        if index > args.limit:
            break
        print(
            f"{index}. {flow_key} "
            f"{flow['source_ip']}:{flow['source_port']} -> "
            f"{flow['destination_ip']}:{flow['destination_port']} "
            f"包数量={len(flow['payload_seq'])} "
            f"持续时间毫秒={flow['flow_duration_ms']:.3f}"
        )


if __name__ == "__main__":
    main()
