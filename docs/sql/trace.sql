-- MySQL dump 10.13  Distrib 8.0.40, for Linux (x86_64)
--
-- Host: localhost    Database: ConfuseWebpage
-- ------------------------------------------------------
-- Server version	8.0.40-0ubuntu0.24.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `http_trace`
--

DROP TABLE IF EXISTS `http_trace`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `http_trace` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `entry_time` datetime NOT NULL COMMENT '入库时间',
  `capture_time` datetime DEFAULT NULL COMMENT '采集时间',
  `timestamp` mediumblob COMMENT '时间戳（绝对）',
  `payload` mediumblob NOT NULL COMMENT 'payload长度+方向',
  `protocol` varchar(30) DEFAULT NULL COMMENT '协议（HTTPs、Vmess、Tor、Obfs4等）',
  `transport_protocol` enum('TCP','UDP') DEFAULT NULL COMMENT '传输层协议',
  `accessed_website` varchar(255) DEFAULT NULL COMMENT '访问网站域名/应用',
  `flownum` int unsigned DEFAULT NULL COMMENT '这个trace中包含的流数量',
  `packet_length` int unsigned DEFAULT NULL COMMENT '包长度',
  `packet_length_no_payload` int unsigned DEFAULT NULL COMMENT '去除payload为0的包长度',
  `collection_machine` varchar(255) DEFAULT NULL COMMENT '采集机器',
  `pcap_path` varchar(255) DEFAULT NULL COMMENT '原始pcap路径',
  PRIMARY KEY (`id`),
  UNIQUE KEY `accessed_website` (`accessed_website`,`capture_time`,`protocol`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-12-24 20:41:35
