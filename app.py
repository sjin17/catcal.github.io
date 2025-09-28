from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime as dt
from functools import wraps
from flask_cors import CORS

# 初始化Flask应用
app = Flask(__name__)
CORS(app)  # 这将允许所有来源访问所有路由

# 配置数据库 - 使用SQLite作为示例，实际部署可更换为MySQL等
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cat_account_book.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')  # 实际部署时应使用环境变量

# 初始化数据库
db = SQLAlchemy(app)

# 数据模型
class User(db.Model):
    """用户模型"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    records = db.relationship('ExpenseRecord', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ExpenseCategory(db.Model):
    """支出分类模型"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    icon = db.Column(db.String(50))  # 存储Font Awesome图标类名
    
    # 关系
    records = db.relationship('ExpenseRecord', backref='category', lazy=True)

class ExpenseRecord(db.Model):
    """支出记录模型"""
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 外键
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('expense_category.id'), nullable=False)

# 创建数据库表
with app.app_context():
    db.create_all()
    # 添加默认分类（如果不存在）
    if not ExpenseCategory.query.first():
        default_categories = [
            ExpenseCategory(name='餐饮', icon='fa-utensils'),
            ExpenseCategory(name='购物', icon='fa-shopping-bag'),
            ExpenseCategory(name='住房', icon='fa-home'),
            ExpenseCategory(name='交通', icon='fa-car'),
            ExpenseCategory(name='猫咪用品', icon='fa-paw')
        ]
        db.session.add_all(default_categories)
        db.session.commit()

# 认证装饰器
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # 从请求头获取token
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            token = auth_header.split(" ")[1] if len(auth_header.split(" ")) > 1 else None
        
        if not token:
            return jsonify({'message': '认证令牌缺失!'}), 401
        
        try:
            # 验证token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            
            if not current_user:
                raise Exception("用户不存在")
                
        except Exception as e:
            return jsonify({'message': '认证失败!', 'error': str(e)}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

# API接口

# 用户认证接口
@app.route('/catcal/api/auth/register', methods=['POST'])
def register():
    """用户注册接口 - 前端注册表单提交到此接口"""
    data = request.get_json()
    
    # 检查必填字段
    if not all(k in data for k in ('username', 'password')):
        return jsonify({'message': '用户名和密码为必填项'}), 400
    
    # 检查用户名是否已存在
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': '用户名已被注册'}), 400
    
    # 创建新用户
    new_user = User(username=data['username'])
    new_user.set_password(data['password'])
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        # 生成token
        token = jwt.encode({
            'user_id': new_user.id,
            'exp': dt.datetime.utcnow() + dt.timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'message': '注册成功',
            'token': token,
            'user': {
                'id': new_user.id,
                'username': new_user.username
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '注册失败', 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """用户登录接口 - 前端登录表单提交到此接口"""
    data = request.get_json()
    
    # 检查必填字段
    if not all(k in data for k in ('username', 'password')):
        return jsonify({'message': '用户名和密码为必填项'}), 400
    
    # 查找用户
    user = User.query.filter_by(username=data['username']).first()
    
    # 验证密码
    if not user or not user.check_password(data['password']):
        return jsonify({'message': '用户名或密码错误'}), 401
    
    # 生成token
    token = jwt.encode({
        'user_id': user.id,
        'exp': dt.datetime.utcnow() + dt.timedelta(days=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'message': '登录成功',
        'token': token,
        'user': {
            'id': user.id,
            'username': user.username
        }
    }), 200

@app.route('/catcal/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """获取当前登录用户信息 - 前端可调用此接口验证登录状态"""
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'created_at': current_user.created_at.isoformat()
    }), 200

# 分类管理接口
@app.route('/catcal/api/categories', methods=['GET'])
@token_required
def get_categories(current_user):
    """获取所有支出分类 - 前端加载分类列表时调用此接口"""
    categories = ExpenseCategory.query.all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'icon': c.icon
    } for c in categories]), 200

@app.route('/catcal/api/categories', methods=['POST'])
@token_required
def add_category(current_user):
    """添加新分类 - 前端添加分类表单提交到此接口"""
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'message': '分类名称为必填项'}), 400
    
    new_category = ExpenseCategory(
        name=data['name'],
        icon=data.get('icon', 'fa-question')
    )
    
    try:
        db.session.add(new_category)
        db.session.commit()
        return jsonify({
            'message': '分类添加成功',
            'category': {
                'id': new_category.id,
                'name': new_category.name,
                'icon': new_category.icon
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '添加分类失败', 'error': str(e)}), 500

@app.route('/catcal/api/categories/<int:category_id>', methods=['DELETE'])
@token_required
def delete_category(current_user, category_id):
    """删除分类 - 前端删除分类时调用此接口"""
    category = ExpenseCategory.query.get_or_404(category_id)
    
    try:
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': '分类已删除'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '删除分类失败', 'error': str(e)}), 500

# 支出记录接口
@app.route('/catcal/api/records', methods=['GET'])
@token_required
def get_records(current_user):
    """获取当前用户的支出记录 - 前端加载历史记录时调用此接口"""
    # 获取查询参数
    year = request.args.get('year', type=int)
    month = request.args.get('month', type=int)
    category_id = request.args.get('category_id', type=int)
    period = request.args.get('period')
    search = request.args.get('search')
    
    # 基础查询
    query = ExpenseRecord.query.filter_by(user_id=current_user.id)
    
    # 按年份筛选
    if year:
        query = query.filter(db.extract('year', ExpenseRecord.date) == year)
    
    # 按月筛选
    if month:
        query = query.filter(db.extract('month', ExpenseRecord.date) == month)
    
    # 按分类筛选
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    # 按日期范围筛选
    if period:
        today = datetime.utcnow().date()
        if period == 'today':
            query = query.filter(ExpenseRecord.date == today)
        elif period == 'week':
            week_start = today - dt.timedelta(days=today.weekday())
            query = query.filter(ExpenseRecord.date >= week_start, ExpenseRecord.date <= today)
        elif period == 'month':
            month_start = today.replace(day=1)
            query = query.filter(ExpenseRecord.date >= month_start, ExpenseRecord.date <= today)
    
    # 按搜索词筛选
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                ExpenseRecord.description.ilike(search_term),
                ExpenseRecord.amount.cast(db.String).ilike(search_term)
            )
        )
    
    # 按日期降序排序
    records = query.order_by(ExpenseRecord.date.desc()).all()
    
    # 格式化响应
    return jsonify([{
        'id': r.id,
        'amount': r.amount,
        'description': r.description,
        'date': r.date.isoformat(),
        'category_id': r.category_id,
        'category_name': r.category.name,
        'category_icon': r.category.icon
    } for r in records]), 200

@app.route('/api/records', methods=['POST'])
@token_required
def add_record(current_user):
    """添加新支出记录 - 前端添加记录表单提交到此接口"""
    data = request.get_json()
    
    # 检查必填字段
    required_fields = ['amount', 'category_id', 'date']
    if not all(k in data for k in required_fields):
        return jsonify({'message': '金额、分类和日期为必填项'}), 400
    
    try:
        # 解析日期
        date_obj = datetime.strptime(data['date'], '%Y-%m-%d').date()
        
        new_record = ExpenseRecord(
            amount=float(data['amount']),
            description=data.get('description', ''),
            date=date_obj,
            user_id=current_user.id,
            category_id=int(data['category_id'])
        )
        
        db.session.add(new_record)
        db.session.commit()
        
        return jsonify({
            'message': '记录添加成功',
            'record': {
                'id': new_record.id,
                'amount': new_record.amount,
                'description': new_record.description,
                'date': new_record.date.isoformat(),
                'category_id': new_record.category_id
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '添加记录失败', 'error': str(e)}), 500

@app.route('/catcal/api/records/<int:record_id>', methods=['PUT'])
@token_required
def update_record(current_user, record_id):
    """更新支出记录 - 前端编辑记录表单提交到此接口"""
    record = ExpenseRecord.query.filter_by(
        id=record_id, 
        user_id=current_user.id
    ).first_or_404()
    
    data = request.get_json()
    
    try:
        if 'amount' in data:
            record.amount = float(data['amount'])
        if 'description' in data:
            record.description = data['description']
        if 'category_id' in data:
            record.category_id = int(data['category_id'])
        if 'date' in data:
            record.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        
        db.session.commit()
        
        return jsonify({
            'message': '记录已更新',
            'record': {
                'id': record.id,
                'amount': record.amount,
                'description': record.description,
                'date': record.date.isoformat(),
                'category_id': record.category_id
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '更新记录失败', 'error': str(e)}), 500

@app.route('/api/records/<int:record_id>', methods=['DELETE'])
@token_required
def delete_record(current_user, record_id):
    """删除支出记录 - 前端删除记录时调用此接口"""
    record = ExpenseRecord.query.filter_by(
        id=record_id, 
        user_id=current_user.id
    ).first_or_404()
    
    try:
        db.session.delete(record)
        db.session.commit()
        return jsonify({'message': '记录已删除'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': '删除记录失败', 'error': str(e)}), 500

# 统计接口
@app.route('/catcal/api/statistics/categories', methods=['GET'])
@token_required
def get_category_stats(current_user):
    """获取分类统计数据 - 前端生成统计图表时调用此接口"""
    # 获取查询参数
    year = request.args.get('year', type=int, default=datetime.utcnow().year)
    month = request.args.get('month', type=int)
    category_id = request.args.get('category_id', type=int)
    
    # 构建查询
    query = ExpenseRecord.query.filter_by(user_id=current_user.id)
    
    if year:
        query = query.filter(db.extract('year', ExpenseRecord.date) == year)
    if month:
        query = query.filter(db.extract('month', ExpenseRecord.date) == month)
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    # 执行查询并按分类分组
    from sqlalchemy import func
    stats_query = query.with_entities(
        ExpenseRecord.category_id,
        func.sum(ExpenseRecord.amount).label('total'),
        func.count(ExpenseRecord.id).label('count')
    ).group_by(ExpenseRecord.category_id).all()
    
    # 获取所有分类
    categories = {c.id: c for c in ExpenseCategory.query.all()}
    
    # 计算总计
    total = sum(stat.total for stat in stats_query)
    
    # 格式化结果
    result = []
    for stat in stats_query:
        category = categories.get(stat.category_id)
        if category:
            percentage = (stat.total / total) * 100 if total > 0 else 0
            result.append({
                'category': {
                    'id': category.id,
                    'name': category.name,
                    'icon': category.icon
                },
                'total': float(stat.total),
                'count': stat.count,
                'percentage': float(percentage)
            })
    
    # 按金额降序排序
    result.sort(key=lambda x: x['total'], reverse=True)
    
    return jsonify({
        'stats': result,
        'total': float(total)
    }), 200

@app.route('/api/statistics/trends', methods=['GET'])
@token_required
def get_trend_stats(current_user):
    """获取趋势统计数据 - 前端生成趋势图表时调用此接口"""
    # 获取查询参数
    year = request.args.get('year', type=int, default=datetime.utcnow().year)
    month = request.args.get('month', type=int)
    period_type = request.args.get('period_type', 'month')  # 'month' 或 'year'
    
    # 构建查询
    query = ExpenseRecord.query.filter_by(user_id=current_user.id)
    
    if year:
        query = query.filter(db.extract('year', ExpenseRecord.date) == year)
    if month:
        query = query.filter(db.extract('month', ExpenseRecord.date) == month)
    
    # 按日或按月分组
    from sqlalchemy import func
    if period_type == 'month' and month:
        # 按月视图：按日分组
        trend_query = query.with_entities(
            db.extract('day', ExpenseRecord.date).label('period'),
            func.sum(ExpenseRecord.amount).label('total')
        ).group_by('period').all()
        
        # 获取当月天数
        if month in [4, 6, 9, 11]:
            total_periods = 30
        elif month == 2:
            # 简单判断闰年
            total_periods = 29 if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0) else 28
        else:
            total_periods = 31
            
        labels = [str(i) for i in range(1, total_periods + 1)]
        
    else:
        # 按年视图：按月分组
        trend_query = query.with_entities(
            db.extract('month', ExpenseRecord.date).label('period'),
            func.sum(ExpenseRecord.amount).label('total')
        ).group_by('period').all()
        
        labels = [str(i) for i in range(1, 13)]  # 1-12月
    
    # 构建结果数据
    trend_data = {str(int(stat.period)): float(stat.total) for stat in trend_query}
    data = [trend_data.get(period, 0) for period in labels]
    
    return jsonify({
        'labels': labels,
        'data': data
    }), 200

# 启动应用
if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5002, debug=True)
