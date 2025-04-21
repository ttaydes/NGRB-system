from scapy.all import sniff, TCP, Raw, IP, UDP, ICMP
import json
from datetime import datetime
import threading
import queue
import logging
import time
import sys
import os
import base64
import psycopg
# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('traffic.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 数据库配置
DB_CONFIG = {
    'dbname': 'ngrb',
    'user': 'postgres',
    'password': '.',
    'host': 'localhost',
    'port': '5432'
}

class TrafficCollector:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.running = False
        self.thread = None
        self.sniff_thread = None
        self.retry_count = 0
        self.max_retries = 3
        self.db_connection = None
        self.db_cursor = None
        self.connect_db()

    def connect_db(self):
        """连接到数据库"""
        try:
            self.db_connection = psycopg.connect(**DB_CONFIG)
            self.db_cursor = self.db_connection.cursor()
            logger.info("Successfully connected to database")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def analyze_packet(self, packet):
        """分析数据包，评估风险等级"""
        risk_level = "low"
        threat_type = None
        status = "normal"

        # 检查可疑端口
        suspicious_ports = [22, 23, 3389, 445, 1433, 3306]
        if packet.haslayer(TCP):
            if packet[TCP].dport in suspicious_ports:
                risk_level = "medium"
                threat_type = "suspicious_port"
                status = "suspicious"

        # 检查异常大的数据包
        if len(packet) > 1500:  # 标准MTU是1500
            risk_level = "medium"
            threat_type = "large_packet"
            status = "suspicious"

        return risk_level, threat_type, status

    def process_payload(self, payload):
        """处理payload数据，将二进制数据转换为base64编码"""
        if payload is None:
            return "null"
        try:
            return payload
        except:
            # 如果无法解码为UTF-8，则转换为base64
            try:
                return base64.b64encode(payload).decode('utf-8')
            except:
                return "null"

    def packet_callback(self, packet):
        """处理捕获的数据包"""
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                protocol = "IP"
                payload = None

                # 提取基本信息
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                packet_size = len(packet)

                # 处理不同协议
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    if packet.haslayer(Raw):
                        payload = self.process_payload(packet[Raw].load)
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                    src_port = 0
                    dst_port = 0
                else:
                    src_port = 0
                    dst_port = 0

                # 分析数据包
                risk_level, threat_type, status = self.analyze_packet(packet)

                # 构建数据包信息
                packet_info = {
                    "timestamp": datetime.now(),
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "protocol": protocol,
                    "packet_size": packet_size,
                    "payload": payload,
                    "risk_level": risk_level,
                    "threat_type": threat_type,
                    "status": status
                }

                # 将数据包信息放入队列
                self.packet_queue.put(packet_info)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def save_to_db(self):
        """将数据包保存到数据库"""
        while self.running:
            try:
                packet_info = self.packet_queue.get(timeout=1)
                try:
                    # 准备SQL语句
                    sql = """
                    INSERT INTO traffic (
                        timestamp, source_ip, source_port, destination_ip, 
                        destination_port, protocol, packet_size, payload,
                        risk_level, threat_type, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    
                    # 准备参数
                    params = (
                        packet_info["timestamp"],
                        packet_info["source_ip"],
                        packet_info["source_port"],
                        packet_info["destination_ip"],
                        packet_info["destination_port"],
                        packet_info["protocol"],
                        packet_info["packet_size"],
                        packet_info["payload"],
                        packet_info["risk_level"],
                        packet_info["threat_type"],
                        packet_info["status"]
                    )

                    # 执行插入
                    self.db_cursor.execute(sql, params)
                    self.db_connection.commit()
                    self.retry_count = 0
                except psycopg.Error as e:
                    logger.error(f"Database error: {e}")
                    self.db_connection.rollback()
                    self.retry_count += 1
                    if self.retry_count < self.max_retries:
                        self.packet_queue.put(packet_info)
                        time.sleep(1)
                    else:
                        # 如果重试次数过多，尝试重新连接数据库
                        try:
                            self.connect_db()
                            self.retry_count = 0
                        except:
                            logger.error("Failed to reconnect to database")
                            time.sleep(5)   
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in save_to_db: {e}")

    def start_sniffing(self):
        """开始捕获流量"""
        try:
            sniff(iface=["WLAN","VMware Network Adapter VMnet8"],prn=self.packet_callback, store=0)
        except Exception as e:
            logger.error(f"Error in sniffing: {e}")
            if self.running:
                time.sleep(1)
                self.start_sniffing()  # 重新开始捕获

    def start(self):
        """启动流量收集"""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self.save_to_db)
        self.thread.daemon = True
        self.thread.start()

        self.sniff_thread = threading.Thread(target=self.start_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

        logger.info("Traffic collector started successfully")

    def stop(self):
        """停止流量收集"""
        self.running = False
        if self.thread:
            self.thread.join()
        if self.sniff_thread:
            self.sniff_thread.join()
        if self.db_cursor:
            self.db_cursor.close()
        if self.db_connection:
            self.db_connection.close()
        logger.info("Traffic collector stopped")

if __name__ == "__main__":
    collector = TrafficCollector()
    try:
        collector.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        collector.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        collector.stop()