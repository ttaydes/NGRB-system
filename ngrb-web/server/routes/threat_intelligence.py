from flask import Blueprint, request, jsonify
from datetime import datetime
from extensions import db
from models.threat_intelligence import (
    IPIntelligence,
    FileIntelligence,
    C2Intelligence,
    TrafficIntelligence
)

bp = Blueprint('threat_intelligence', __name__)

@bp.route('/api/threat-intelligence', methods=['GET'])
def get_intelligence():
    try:
        # 获取所有类型的情报
        ip_intel = IPIntelligence.query.all()
        file_intel = FileIntelligence.query.all()
        c2_intel = C2Intelligence.query.all()
        traffic_intel = TrafficIntelligence.query.all()
        
        return jsonify({
            'success': True,
            'data': {
                'ip': [item.to_dict() for item in ip_intel],
                'file': [item.to_dict() for item in file_intel],
                'c2': [item.to_dict() for item in c2_intel],
                'traffic': [item.to_dict() for item in traffic_intel]
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/threat-intelligence', methods=['POST'])
def add_intelligence():
    try:
        data = request.get_json()
        intel_type = data.get('type')
        
        if not intel_type:
            return jsonify({
                'success': False,
                'message': '缺少情报类型'
            }), 400
        
        # 根据类型创建不同的情报对象
        if intel_type == 'ip':
            intelligence = IPIntelligence(
                ip=data['ip'],
                type=data['threat_type'],
                source=data['source'],
                description=data['description'],
                first_seen=datetime.now()
            )
        elif intel_type == 'file':
            intelligence = FileIntelligence(
                hash=data['hash'],
                type=data['threat_type'],
                source=data['source'],
                description=data['description'],
                first_seen=datetime.now()
            )
        elif intel_type == 'c2':
            intelligence = C2Intelligence(
                domain=data['domain'],
                ip=data.get('ip', ''),
                type=data['threat_type'],
                source=data['source'],
                description=data['description'],
                first_seen=datetime.now()
            )
        elif intel_type == 'traffic':
            intelligence = TrafficIntelligence(
                name=data['name'],
                type=data['threat_type'],
                source=data['source'],
                description=data['description'],
                first_seen=datetime.now()
            )
        else:
            return jsonify({
                'success': False,
                'message': '不支持的情报类型'
            }), 400
        
        db.session.add(intelligence)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '添加成功',
            'data': intelligence.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/threat-intelligence/<int:id>', methods=['DELETE'])
def delete_intelligence(id):
    try:
        # 尝试从所有类型的情报表中删除
        for model in [IPIntelligence, FileIntelligence, C2Intelligence, TrafficIntelligence]:
            intelligence = model.query.get(id)
            if intelligence:
                db.session.delete(intelligence)
                db.session.commit()
                return jsonify({
                    'success': True,
                    'message': '删除成功'
                })
        
        return jsonify({
            'success': False,
            'message': '未找到指定ID的情报'
        }), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@bp.route('/api/threat-intelligence/check', methods=['POST'])
def check_intelligence():
    try:
        data = request.get_json()
        check_type = data.get('type')
        value = data.get('value')
        
        if not check_type or not value:
            return jsonify({
                'success': False,
                'message': '缺少必要参数'
            }), 400
        
        result = {
            'found': False,
            'details': None
        }
        
        # 根据类型检查不同的情报表
        if check_type == 'ip':
            intelligence = IPIntelligence.query.filter_by(ip=value).first()
        elif check_type == 'hash':
            intelligence = FileIntelligence.query.filter_by(hash=value).first()
        elif check_type == 'domain':
            intelligence = C2Intelligence.query.filter_by(domain=value).first()
        else:
            return jsonify({
                'success': False,
                'message': '不支持的类型'
            }), 400
        
        if intelligence:
            result['found'] = True
            result['details'] = intelligence.to_dict()
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500 