from flask import Blueprint, request, jsonify
from flask_socketio import emit
from datetime import datetime, timedelta
from extensions import db, socketio
from models.traffic import Traffic

bp = Blueprint('traffic', __name__)

@bp.route('/api/traffic', methods=['GET'])
def get_traffic():
    """获取流量数据"""
    try:
        limit = request.args.get('limit', default=100, type=int)
        risk_level = request.args.get('risk_level')
        protocol = request.args.get('protocol')
        time_range = request.args.get('time_range', '1h')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        query = Traffic.query
        if risk_level:
            query = query.filter_by(risk_level=risk_level)
        if protocol:
            query = query.filter_by(protocol=protocol)
        
        # 优先使用日期范围过滤
        if start_date and end_date:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)  # 包含结束日期
            query = query.filter(Traffic.timestamp >= start, Traffic.timestamp < end)
        else:
            # 如果没有日期范围，使用时间范围
            if time_range == '1h':
                query = query.filter(Traffic.timestamp >= datetime.now() - timedelta(hours=1))
            elif time_range == '24h':
                query = query.filter(Traffic.timestamp >= datetime.now() - timedelta(days=1))
            elif time_range == '7d':
                query = query.filter(Traffic.timestamp >= datetime.now() - timedelta(days=7))

        traffic = query.order_by(Traffic.timestamp.desc()).limit(limit).all()

        # 统计信息
        total = query.count()
        suspicious = query.filter_by(status='suspicious').count()
        malicious = query.filter_by(status='malicious').count()

        return jsonify({
            'traffic': [t.to_dict() for t in traffic],
            'total': total,
            'suspicious': suspicious,
            'malicious': malicious
        })
    except Exception as e:
        db.session.rollback()  # 避免事务挂起
        return jsonify({'error': str(e)}), 500

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

@bp.route('/api/traffic', methods=['POST'])
def add_traffic():
    """添加新的流量数据"""
    try:
        data = request.get_json()
        traffic = Traffic(
            source_ip=data['source_ip'],
            source_port=data['source_port'],
            destination_ip=data['destination_ip'],
            destination_port=data['destination_port'],
            protocol=data['protocol'],
            packet_size=data['packet_size'],
            payload=data.get('payload'),
            risk_level=data['risk_level'],
            threat_type=data.get('threat_type'),
            status=data['status']
        )
        db.session.add(traffic)
        db.session.commit()
        return jsonify({'message': 'Traffic data added successfully'}), 201
    except Exception as e:
        db.session.rollback()  # 关键：失败插入后清空事务状态
        return jsonify({'error': str(e)}), 400
