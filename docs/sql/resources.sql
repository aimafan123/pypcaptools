-- ----------------------------
-- Table structure for resources
-- ----------------------------
DROP TABLE IF EXISTS `resources`;
CREATE TABLE `resources` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `flow_id` bigint NOT NULL COMMENT '关联到flows表的ID',
  `stream_id` int unsigned DEFAULT NULL COMMENT 'HTTP/2的流ID',
  `url` text COMMENT '资源的完整URL',
  `http_status` smallint DEFAULT NULL COMMENT 'HTTP状态码 (e.g., 200, 204)',
  `content_type` varchar(255) DEFAULT NULL COMMENT '资源类型 (e.g., text/html, application/javascript)',
  `resource_size_bytes` bigint unsigned DEFAULT NULL COMMENT '资源大小 (字节)',
  `server_packet_count` int unsigned DEFAULT NULL COMMENT '传输该资源的服务器包数量',
  `latency_ms` double DEFAULT NULL COMMENT '资源加载延迟 (毫秒)',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_flow_id` (`flow_id`),
  CONSTRAINT `fk_resources_flow_id` FOREIGN KEY (`flow_id`) REFERENCES `flows` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='存储Flow中承载的具体资源，作为模型训练的标签';