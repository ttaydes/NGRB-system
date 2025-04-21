import os

# Database configuration
DATABASE_CONFIG = {
    'url': 'postgresql://postgres:.@localhost:5432/ngrb'  # 格式: postgresql://用户名:密码@主机:端口/数据库名
}

# Application configuration
APP_CONFIG = {
    'SECRET_KEY': os.urandom(24),
    'DEBUG': True
}

# Traffic collector configuration
TRAFFIC_CONFIG = {
    'interface': '以太网适配器 VMware Network Adapter VMnet8',  # Windows下可能需要修改为实际的网络接口名称
    'server_url': 'http://localhost:5000/api/traffic',
    'batch_size': 100,
    'update_interval': 5  # seconds
}

class Config:
    # 数据库配置
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg://postgres:.@localhost:5432/ngrb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # SocketIO配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev'
    SOCKETIO_MESSAGE_QUEUE = 'redis://localhost:6379/0'
    
    # 其他配置
    TRAFFIC_UPDATE_INTERVAL = 1  # 秒   