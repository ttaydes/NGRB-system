from extensions import db
from loguru import logger
import json

class DnsThreatHunter:
    def __init__(self, packets_info,db_cursor,db_connection):
        self.packets_info = json.loads(packets_info)
        self.db_cursor = db_cursor
        self.db_connection = db_connection

    def detect_threat(self):
        # 检测c2
        sql = """
        select confidence,severity from c2_servers where domain = %s
        """
        self.db_cursor.execute(sql, (self.packets_info['name'],))
        self.db_connection.commit()
        c2_info = self.db_cursor.fetchone()
        if c2_info:
            return {
                "category": "c2",
                "confidence": c2_info[0],
                "severity": c2_info[1]
            }

        else:
            return None

