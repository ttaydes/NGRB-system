from flask import Blueprint, request, jsonify
from flask_socketio import emit
from datetime import datetime, timedelta
from extensions import db, socketio
from models.traffic import Traffic
import dateutil.parser

bp = Blueprint('traffic', __name__)

@bp.route('/api/traffic', methods=['GET'])
def get_traffic():
    """获取流量数据"""
    try:
        # 分页参数
        limit = request.args.get('limit', default=20, type=int)
        offset = request.args.get('offset', default=0, type=int)
        
        # 筛选参数
        source_ip = request.args.get('source_ip')
        destination_ip = request.args.get('destination_ip')
        protocol = request.args.get('protocol')
        risk_level = request.args.get('risk_level')
        
        # 时间范围参数
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        time_range = request.args.get('time_range', '1h')
        traffic_type = request.args.get('traffic_type')
        # 构建查询
        query = Traffic.query
        
        # 应用IP过滤
        if source_ip:
            query = query.filter(Traffic.source_ip.like(f'%{source_ip}%'))
        if destination_ip:
            query = query.filter(Traffic.destination_ip.like(f'%{destination_ip}%'))
        
        # 应用威胁类型过滤
        if traffic_type:
            query = query.filter(Traffic.threat_type.like(f'%{traffic_type}%'))
        # 应用协议过滤
        if protocol:
            query = query.filter_by(protocol=protocol)
        
        # 应用风险等级过滤
        if risk_level:
            query = query.filter_by(risk_level=risk_level)
        
        # 应用时间范围过滤
        if start_time and end_time:
            try:
                # 使用 dateutil.parser 解析各种格式的日期字符串
                start = dateutil.parser.parse(start_time)
                end = dateutil.parser.parse(end_time)
                query = query.filter(Traffic.timestamp >= start, Traffic.timestamp <= end)
            except Exception as e:
                return jsonify({'error': f'Invalid date format: {str(e)}'}), 400
        else:
            # 使用预设时间范围
            now = datetime.now()
            if time_range == '1h':
                query = query.filter(Traffic.timestamp >= now - timedelta(hours=1))
            elif time_range == '24h':
                query = query.filter(Traffic.timestamp >= now - timedelta(days=1))
            elif time_range == '7d':
                query = query.filter(Traffic.timestamp >= now - timedelta(days=7))

        # 获取总数
        total = query.count()

        # 应用分页
        traffic = query.order_by(Traffic.timestamp.desc()).offset(offset).limit(limit).all()

        # 统计信息
        suspicious = query.filter_by(risk_level='medium').count()
        malicious = query.filter_by(risk_level='high').count()

        # 获取统计数据
        stats = {
            'hourly_stats': get_hourly_stats(query),
            'risk_stats': get_risk_stats(query)
        }

        return jsonify({
            'traffic': [t.to_dict() for t in traffic],
            'total': total,
            'suspicious': suspicious,
            'malicious': malicious,
            'stats': stats
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

def get_hourly_stats(query):
    """获取小时统计"""
    hourly_stats = []
    now = datetime.now()
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)
        count = query.filter(
            Traffic.timestamp >= hour_start,
            Traffic.timestamp < hour_end
        ).count()
        hourly_stats.append({
            'hour': hour_start.strftime('%H:00'),
            'count': count
        })
    return hourly_stats

def get_risk_stats(query):
    """获取风险等级统计"""
    risk_stats = []
    for risk in ['low', 'medium', 'high']:
        count = query.filter_by(risk_level=risk).count()
        risk_stats.append({
            'risk_level': risk,
            'count': count
        })
    return risk_stats

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('request_traffic_stats')
def handle_traffic_stats():
    """处理流量统计请求"""
    try:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)

        hourly_stats = []
        for i in range(24):
            hour_start = start_time + timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            count = db.session.query(Traffic).filter(
                Traffic.timestamp >= hour_start,
                Traffic.timestamp < hour_end
            ).count()
            hourly_stats.append({
                'hour': hour_start.strftime('%H:00'),
                'count': count
            })

        protocol_stats = []
        for protocol in ['TCP', 'UDP', 'ICMP']:
            count = db.session.query(Traffic).filter_by(protocol=protocol).count()
            protocol_stats.append({
                'protocol': protocol,
                'count': count
            })

        risk_stats = []
        for risk in ['low', 'medium', 'high']:
            count = db.session.query(Traffic).filter_by(risk_level=risk).count()
            risk_stats.append({
                'risk_level': risk,
                'count': count
            })

        emit('traffic_stats', {
            'hourly_stats': hourly_stats,
            'protocol_stats': protocol_stats,
            'risk_stats': risk_stats
        })
    except Exception as e:
        db.session.rollback()  # 关键
        emit('error', {'message': str(e)})

# @bp.route('/api/traffic', methods=['POST'])
# def add_traffic():
#     """添加新的流量数据"""
#     try:
#         data = request.get_json()
        
#         traffic = Traffic(
#             source_ip=data['source_ip'],
#             source_port=data['source_port'],
#             destination_ip=data['destination_ip'],
#             destination_port=data['destination_port'],
#             protocol=data['protocol'],
#             packet_size=data['packet_size'],
#             payload=data.get('payload'),
#             header_body=data.get('header_body'),
#             risk_level=data['risk_level'],
#             threat_type=data.get('threat_type'),
#             status=data['status']
#         )
#         db.session.add(traffic)
#         db.session.commit()
        
#         # 发送实时更新
#         socketio.emit('traffic_update', {
#             'stats': {
#                 'total': Traffic.query.count(),
#                 'suspicious': Traffic.query.filter_by(status='suspicious').count(),
#                 'malicious': Traffic.query.filter_by(status='malicious').count()
#             },
#             'recent': [traffic.to_dict()]
#         })
        
#         return jsonify({'message': 'Traffic data added successfully'}), 201
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'error': str(e)}), 400
