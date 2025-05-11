from utils.redis_config import redis_config
from loguru import logger
import json
from datetime import datetime, timedelta

class RedisUtils:
    def __init__(self):
        self.redis_client = redis_config.get_client()

    def cache_security_data(self, data, expire_time=300):
        """缓存安全态势数据"""
        try:
            key = "security_data"
            self.redis_client.setex(key, expire_time, json.dumps(data))
            logger.info("Security data cached successfully")
        except Exception as e:
            logger.error(f"Failed to cache security data: {str(e)}")

    def get_cached_security_data(self):
        """获取缓存的安全态势数据"""
        try:
            key = "security_data"
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Failed to get cached security data: {str(e)}")
            return None

    def add_alert(self, alert_data):
        """添加新的告警到队列"""
        try:
            key = "alert_queue"
            alert_data['timestamp'] = datetime.now().isoformat()
            self.redis_client.lpush(key, json.dumps(alert_data))
            # 保持队列长度在1000条以内
            self.redis_client.ltrim(key, 0, 999)
            logger.info("Alert added to queue successfully")
        except Exception as e:
            logger.error(f"Failed to add alert to queue: {str(e)}")

    def get_recent_alerts(self, count=100):
        """获取最近的告警"""
        try:
            key = "alert_queue"
            alerts = self.redis_client.lrange(key, 0, count-1)
            return [json.loads(alert) for alert in alerts]
        except Exception as e:
            logger.error(f"Failed to get recent alerts: {str(e)}")
            return []

    def cache_user_session(self, session_id, user_data, expire_time=3600):
        """缓存用户会话信息"""
        try:
            key = f"session:{session_id}"
            self.redis_client.setex(key, expire_time, json.dumps(user_data))
            logger.info(f"User session cached successfully: {session_id}")
        except Exception as e:
            logger.error(f"Failed to cache user session: {str(e)}")

    def get_user_session(self, session_id):
        """获取用户会话信息"""
        try:
            key = f"session:{session_id}"
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Failed to get user session: {str(e)}")
            return None

    def delete_user_session(self, session_id):
        """删除用户会话"""
        try:
            key = f"session:{session_id}"
            self.redis_client.delete(key)
            logger.info(f"User session deleted successfully: {session_id}")
        except Exception as e:
            logger.error(f"Failed to delete user session: {str(e)}")

    def cache_threat_stats(self, stats_data, expire_time=300):
        """缓存威胁统计数据"""
        try:
            key = "threat_stats"
            self.redis_client.setex(key, expire_time, json.dumps(stats_data))
            logger.info("Threat stats cached successfully")
        except Exception as e:
            logger.error(f"Failed to cache threat stats: {str(e)}")

    def get_cached_threat_stats(self):
        """获取缓存的威胁统计数据"""
        try:
            key = "threat_stats"
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Failed to get cached threat stats: {str(e)}")
            return None

# 创建全局Redis工具实例
redis_utils = RedisUtils() 