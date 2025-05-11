from flask import Blueprint, jsonify,request
from datetime import datetime, timedelta
from models.traffic import Traffic
from models.host import Host,SecurityScan
from models.file import File
from models.alert import Alert
from models.threat_intelligence import MaliciousIP,C2Server
from extensions import db
import random
from loguru import logger
bp = Blueprint('situation_awareness', __name__)
import requests
from utils.redis_utils import redis_utils

def generate_test_data():
    """生成测试数据"""
    # 生成告警数据
    alert_types = ['流量异常', '文件威胁', '主机入侵', '系统漏洞', '恶意扫描']
    risk_levels = ['high', 'medium', 'low']
    sources = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5']
    
    for _ in range(50):
        alert = Alert(
            timestamp=datetime.now() - timedelta(hours=random.randint(0, 24)),
            type=random.choice(alert_types),
            source=random.choice(sources),
            description=f"检测到{random.choice(['可疑', '异常', '恶意'])}{random.choice(['流量', '行为', '访问'])}",
            risk_level=random.choice(risk_levels),
            status='unhandled'
        )
        db.session.add(alert)
  
 
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error generating test data: {e}")

@bp.route('/api/situation/overview', methods=['GET'])
def get_situation_overview():
    """获取安全态势概览数据"""
    try:
        time_range = request.args.get('timeRange')
        alert_type = request.args.get('alertType', 'source')
        
        # 尝试从Redis缓存获取数据
        cached_data = redis_utils.get_cached_security_data()
        if cached_data:
            logger.info("Using cached security data")
            # 确保缓存数据包含所有必要字段
            if all(key in cached_data for key in ['securityIndex', 'trendTimes', 'trendValues']):
                return jsonify(cached_data)
            else:
                logger.warning("Cached data missing required fields, fetching fresh data")
        
        # 如果没有数据，生成测试数据
        if not Alert.query.first():
            generate_test_data()
        
        # 获取时间范围
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=int(time_range))
        
        # 获取流量数据
        traffic = Traffic.query.filter(
            Traffic.timestamp >= start_time,
            Traffic.timestamp <= end_time
        ).all()
        
        # 生成安全态势曲线数据
        trend_times = []
        trend_values = []
        
        # 根据时间范围生成时间点
        if time_range == '24':
            interval = 1  # 1小时
            points = 24
        elif time_range == '168':
            interval = 6  # 6小时
            points = 28
        else:  # 720 (30天)
            interval = 24  # 24小时
            points = 30
            
        for i in range(points):
            time_point = start_time + timedelta(hours=i * interval)
            end_point = time_point + timedelta(hours=interval)
            
            # 计算该时间段内的安全指数
            period_traffic = [t for t in traffic if 
                            t.timestamp >= time_point and 
                            t.timestamp < end_point]
            
            total = len(period_traffic)
            suspicious = len([t for t in period_traffic if t.risk_level == 'medium'])
            malicious = len([t for t in period_traffic if t.risk_level == 'high'])
            
            security_index = 100
            if total > 0:
                security_index = int(100 - (suspicious * 0.5 + malicious) / total * 100)
            
            trend_times.append(time_point.strftime('%Y-%m-%d %H:00'))
            trend_values.append(security_index)
        
        # 计算当前安全指数
        total_traffic = len(traffic)
        suspicious_traffic = len([t for t in traffic if t.risk_level == 'medium'])
        malicious_traffic = len([t for t in traffic if t.risk_level == 'high'])
        
        security_index = 100
        if total_traffic > 0:
            security_index = int(100 - (suspicious_traffic * 0.5 + malicious_traffic) / total_traffic * 100)
        
        # 获取最近24小时的文件威胁数据
        file_threats = File.query.filter(
            File.detection_time >= start_time,
            File.detection_time <= end_time
        ).all()

        malicious_ips = MaliciousIP.query.filter(
            MaliciousIP.first_seen >= start_time,
            MaliciousIP.first_seen <= end_time
        ).all() 

        c2_servers = C2Server.query.filter(
            C2Server.updated_at >= start_time,
            C2Server.updated_at <= end_time
        ).all()

        # 获取主机数据
        hosts = Host.query.all()
        active_hosts = len([h for h in hosts if h.status == "online"])
     
        # 获取告警数据
        host_threat = SecurityScan.query.filter(
            SecurityScan.scan_time >= start_time,
            SecurityScan.scan_time <= end_time
        ).all()
        
        # 计算不同类型的告警统计
        alert_stats = {
           
            'traffic': {
                'high': len([a for a in traffic if a.risk_level == 'high']),
                'medium': len([a for a in traffic if a.risk_level == 'medium']),
                'low': len([a for a in traffic if a.risk_level == 'low'])
            },
            'file': {
                'high': len([a for a in file_threats if a.threat_level == 'malicious']),
                'medium': len([a for a in file_threats if a.threat_level == 'suspicious']),
                'low': len([a for a in file_threats if a.threat_level == 'clean'])
            },
            'host': {
                'high': len([a for a in host_threat if a.risk_level == 'high']),
                'medium': len([a for a in host_threat if a.risk_level == 'medium']),
                'low': len([a for a in host_threat if a.risk_level == 'low'])
            }
        }
        
        # 计算威胁来源分布
        threat_sources = {}
        count = 0
        # 流量具体每条对应威胁类型的数据
        for t in traffic:
            if t.traffic_type:
                threat_sources[t.traffic_type] = threat_sources.get(t.traffic_type, 0) + 1
        
        #文件威胁的数据
        count = 0
        for f in file_threats:
            print(f.md5)
            if f.md5:
                count += 1
        threat_sources['file_threat_md5'] = count

        count = 0
        for m in malicious_ips:
            if m.ip_address:
                count += 1
        threat_sources['malicious_ip'] = count

        count = 0   
        for c in c2_servers:
            if c.ip_address or c.domain:
                count += 1
        threat_sources['c2_server'] = count


        print(threat_sources)

        # 生成威胁词云数据
        word_cloud = []
        threat_keywords = ['c2', 'top10','webshell','poc','cve','rce','malware','ip','sensitive']
        for keyword in threat_keywords:
            count = len([t for t in traffic if keyword in t.threat_type])
            if count > 0:
                word_cloud.append({
                    'name': keyword,
                    'value': count * 10
                })
        # 添加省份威胁数量测试数据
        province_threats = [
            {'name': '北京', 'value': 156},
            {'name': '上海', 'value': 98},
            {'name': '广东', 'value': 245},
            {'name': '浙江', 'value': 132},
            {'name': '江苏', 'value': 87},
            {'name': '四川', 'value': 65},
            {'name': '湖北', 'value': 43},
            {'name': '福建', 'value': 76},
            {'name': '山东', 'value': 54},
            {'name': '河南', 'value': 32},
            {'name': '重庆', 'value': 45},
            {'name': '陕西', 'value': 38},
            {'name': '湖南', 'value': 67},
            {'name': '河北', 'value': 29},
            {'name': '天津', 'value': 41}
        ]
        
        response_data = {
            'securityIndex': security_index,
            'activeHosts': active_hosts,
            'alertStats': alert_stats,
            'threatSources': [{'name': k, 'value': v} for k, v in threat_sources.items()],
            'trendTimes': trend_times,
            'trendValues': trend_values,
            'wordCloud': word_cloud,
            'provinceThreats': province_threats
        }
        
        # 记录数据日志
        logger.info(f"Generated security data - Security Index: {security_index}")
        logger.info(f"Trend data points: {len(trend_times)}")
        logger.info(f"First trend value: {trend_values[0] if trend_values else 'No data'}")
        
        # 缓存数据到Redis
        redis_utils.cache_security_data(response_data)
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error in get_situation_overview: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/api/situation/alerts', methods=['GET'])
def get_recent_alerts():
    """获取最近告警数据"""
    try:
        # 尝试从Redis获取告警数据
        cached_alerts = redis_utils.get_recent_alerts()
        if cached_alerts:
            return jsonify(cached_alerts)
            
        # 如果没有数据，生成测试数据
        if not Alert.query.first():
            generate_test_data()
            
        # 获取最近100条告警
        alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(100).all()
        
        alert_data = [{
            'id': alert.id,
            'timestamp': alert.timestamp.isoformat(),
            'type': alert.type,
            'source': alert.source,
            'description': alert.description,
            'risk_level': alert.risk_level
        } for alert in alerts]
        
        # 将告警数据添加到Redis队列
        for alert in alert_data:
            redis_utils.add_alert(alert)
        
        return jsonify(alert_data)
    except Exception as e:
        logger.error(f"Error in get_recent_alerts: {str(e)}")
        return jsonify({'error': str(e)}), 500

    """获取指定主机的安全态势数据"""
    try:
        # 如果没有数据，生成测试数据
        if not Host.query.first():
            generate_test_data()
            
        # 获取主机信息
        host = Host.query.get_or_404(host_id)
        
        # 获取最近24小时的流量数据
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        traffic = Traffic.query.filter(
            Traffic.source_ip == host.ip,
            Traffic.timestamp >= start_time,
            Traffic.timestamp <= end_time
        ).all()
        
        # 获取最近24小时的文件威胁数据
        file_threats = File.query.filter(
            File.detection_time >= start_time,
            File.detection_time <= end_time
        ).all()

        malicious_ips = MaliciousIP.query.filter(
            MaliciousIP.first_seen >= start_time,
            MaliciousIP.first_seen <= end_time
        ).all() 

        c2_servers = C2Server.query.filter(
            C2Server.updated_at >= start_time,
            C2Server.updated_at <= end_time
        ).all()

        # 计算安全指数
        total_traffic = len(traffic)
        suspicious_traffic = len([t for t in traffic if t.status == 'suspicious'])
        malicious_traffic = len([t for t in traffic if t.status == 'malicious'])
        
        security_index = 100
        if total_traffic > 0:
            security_index = int(100 - (suspicious_traffic * 0.5 + malicious_traffic) / total_traffic * 100)
        
        # 计算告警统计
        alert_stats = {
            'high': len([t for t in traffic if t.risk_level == 'high']),
            'medium': len([t for t in traffic if t.risk_level == 'medium']),
            'low': len([t for t in traffic if t.risk_level == 'low'])
        }
        
       
        # 计算威胁来源分布
        threat_sources = {}
        for t in traffic:
            if t.traffic_type:
                threat_sources['taffic_threat_type'] = threat_sources.get(t.traffic_type, 0) + 1
        
        #文件威胁的数据
        for f in file_threats:
            if f.threat_type:
                threat_sources['file_threat_md5'] = file_threats.get(f.md5, 0) + 1


        for m in malicious_ips:
            if m.ip_address:
                threat_sources['malicious_ip'] = malicious_ips.get(m.ip_address, 0) + 1

        for c in c2_servers:
            if c.ip_address:
                threat_sources['c2_server'] = c2_servers.get(c.ip_address, 0) + 1 or c2_servers.get(c.domain, 0) + 1

        # 生成安全态势曲线数据
        trend_times = []
        trend_values = []
        for i in range(24):
            time_point = start_time + timedelta(hours=i)
            count = len([t for t in traffic if 
                        t.timestamp >= time_point and 
                        t.timestamp < time_point + timedelta(hours=1)])
            trend_times.append(time_point.strftime('%H:00'))
            trend_values.append(count)
        
        # 生成威胁词云数据
        word_cloud = []
        logger.info([t for t in traffic if t.threat_type and keyword in t.threat_type])
        threat_keywords = ['c2', 'top10','webshell','cnc','ddos','rce','xss','sql','webshell']
        for keyword in threat_keywords:
            count = len([t for t in traffic if t.threat_type and keyword in t.threat_type])
            if count > 0:
                word_cloud.append({
                    'name': keyword,
                    'value': count * 100
                })
        
        return jsonify({
            'securityIndex': security_index,
            'alertStats': alert_stats,
            'threatSources': [{'name': k, 'value': v} for k, v in threat_sources.items()],
            'trendTimes': trend_times,
            'trendValues': trend_values,
            'wordCloud': word_cloud
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500 