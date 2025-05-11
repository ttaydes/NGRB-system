import math
from loguru import logger
import json
class IcmpThreatHunter:
    def __init__(self, packets_info):
        self.packets_info = packets_info
        # def calculate_entropy(data):
        #     if not data:
        #         return 0
        #     prob = [float(data.count(c)) / len(data) for c in set(data)]
        #     return -sum([p * math.log(p, 2) for p in prob])

    def detect_threat(self):
        # pingtunel的特征检测
        logger.info(f"============ICMP数据{self.packets_info['data']}")
        # entropy = self.calculate_entropy(self.packets_info['data'])
        if int(self.packets_info['size']) > 100:
            return {
                "category": "tool",
                "confidence": 0.8,
                "severity": "medium"
            }
        else:
            return None 
