-- ----------------------------
-- Table structure for traces
-- ----------------------------
DROP TABLE IF EXISTS `traces`;
CREATE TABLE `traces` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `accessed_website` varchar(255) NOT NULL COMMENT '访问的目标网站域名，作为主要标签',
  `capture_time` datetime NOT NULL COMMENT '数据采集的起始时间',
  `timestamps_seq` JSON COMMENT '包时间戳序列 (相对于流开始时间)，用于模型输入',
  `payload_seq` JSON NOT NULL COMMENT '包大小序列',
  `direction_seq` JSON NOT NULL COMMENT '包方向序列 (-表示出, +表示入)，用于模型输入',
  `protocol` varchar(30) DEFAULT 'HTTPS' COMMENT '应用层协议 (e.g., HTTPS, QUIC)',
  `collection_machine` varchar(255) DEFAULT NULL COMMENT '采集机器的标识',
  `pcap_path` varchar(255) NOT NULL COMMENT '原始pcap文件的存储路径',
  `json_path` varchar(255) NOT NULL COMMENT '对应的json标签文件路径',
  `flow_count` int unsigned DEFAULT NULL COMMENT '此trace中包含的流数量',
  `total_packet_count` int unsigned DEFAULT NULL COMMENT '此trace的总包数',
  `metadata` json DEFAULT NULL COMMENT '扩展字段，用于存储额外信息 (如浏览器版本, 操作系统等)',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_website_capture_time` (`accessed_website`,`capture_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='存储每一次完整的网页访问记录 (Trace)';