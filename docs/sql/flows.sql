-- ----------------------------
-- Table structure for flows
-- ----------------------------
DROP TABLE IF EXISTS `flows`;
CREATE TABLE `flows` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `trace_id` bigint NOT NULL COMMENT '关联到traces表的ID',
  `source_ip` varchar(45) NOT NULL COMMENT '源IP地址',
  `destination_ip` varchar(45) NOT NULL COMMENT '目的IP地址',
  `source_port` smallint unsigned NOT NULL COMMENT '源端口',
  `destination_port` smallint unsigned NOT NULL COMMENT '目的端口',
  `transport_protocol` enum('TCP','UDP') NOT NULL COMMENT '传输层协议',
  `sni` varchar(255) DEFAULT NULL COMMENT 'TLS握手中的SNI (Server Name Indication)',
  `flow_start_time_ms` double DEFAULT NULL COMMENT '流的开始时间 (相对于trace开始的毫秒数)',
  `flow_duration_ms` double DEFAULT NULL COMMENT '流的持续时间 (毫秒)',
  `timestamps_seq` JSON COMMENT '包时间戳序列 (相对于流开始时间)，用于模型输入',
  `payload_seq` JSON NOT NULL COMMENT '包大小序列',
  `direction_seq` JSON NOT NULL COMMENT '包方向序列 (-表示出, +表示入)，用于模型输入',
  `http_version` varchar(16) DEFAULT NULL COMMENT 'HTTP协议版本，如 http1.1 或 http2',
  `trace_packet_indices` json DEFAULT NULL COMMENT '本flow包含的数据包在traces主序列中的索引列表 (JSON数组, e.g., [0, 2, 3, 7])',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_trace_id` (`trace_id`),
  CONSTRAINT `fk_flows_trace_id` FOREIGN KEY (`trace_id`) REFERENCES `traces` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='存储Trace中的单个网络流 (Flow)，作为模型输入';