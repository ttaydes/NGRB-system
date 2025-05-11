import redis
from loguru import logger

class RedisConfig:
    def __init__(self):
        self.redis_client = None
        self.connect()

    def connect(self):
        try:
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True
            )
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Redis connection failed: {str(e)}")
            raise

    def get_client(self):
        return self.redis_client

# 创建全局Redis实例
redis_config = RedisConfig() 