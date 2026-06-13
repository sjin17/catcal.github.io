# -*- coding: utf-8 -*-
"""
写作平台后端 —— 在原「记账」后端基础上合并/改造而来。
  · 复用：账号体系（注册 / 登录 / JWT），原有账号继续可用。
  · 新增：作品(Work) 的增删改查 + 复制 +（可选）码字统计。
  · 已移除：原记账专用接口（分类 / 账目 / 统计），新前端用不到。

依赖（原 pyproject 已包含）：flask  flask-cors  flask-sqlalchemy  pyjwt
所有【朋友需配置】的地方都在下方用 ⚠️ 标出，共 4 处。
"""

import os
import json
import datetime as dt
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)

# ============================================================================
# ⚠️【朋友需配置 1】CORS 允许的来源
#   开发阶段用 "*" 即可；上线后强烈建议收紧到正式域名，防止别的站点盗用接口。
#   用环境变量 CORS_ORIGIN 覆盖，例如：  export CORS_ORIGIN=https://81818.top
# ============================================================================
CORS(app, resources={r"/*": {"origins": os.environ.get("CORS_ORIGIN", "*")}})

# ============================================================================
# ⚠️【朋友需配置 2】数据库地址
#   默认沿用原来的 SQLite 文件（保留已有账号）。若要换 MySQL/PostgreSQL，
#   设环境变量 DATABASE_URL，例如：  export DATABASE_URL=mysql+pymysql://user:pwd@host/db
# ============================================================================
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///cat_account_book.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ============================================================================
# ⚠️【朋友需配置 3 · 重要安全】JWT 签名密钥 SECRET_KEY
#   这是签发登录令牌的密钥。绝对不要用下面的默认值上线，
#   否则任何人都能伪造登录令牌、冒充用户。
#   生产请用环境变量覆盖： export SECRET_KEY=<一串长随机字符串>
#   生成示例：  python -c "import secrets; print(secrets.token_hex(32))"
# ============================================================================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key_请在生产用环境变量覆盖')

db = SQLAlchemy(app)


# ----------------------------- 数据模型 -----------------------------
class User(db.Model):
    """用户（沿用原表，原有账号继续可用）"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)


class Work(db.Model):
    """一部作品 = 一条记录；整份作品 JSON 原样存在 data 里。
    后端不需要理解作品内部字段，存取即可；字段含义由前端负责。"""
    id = db.Column(db.String(40), primary_key=True)        # 用前端生成的 id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'),
                        nullable=False, index=True)
    title = db.Column(db.String(200), default='未命名')     # 冗余，列表页显示用
    word_count = db.Column(db.Integer, default=0)           # 冗余，列表页显示用
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    data = db.Column(db.Text, nullable=False, default='{}')  # 整份作品 JSON


class Stat(db.Model):
    """可选：码字统计（跨设备的码字日历）。不需要可把这个类和下面 /stats 两个接口一起删掉。"""
    user_id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Text, default='{}')   # {"2026-06-13": 1280, ...}


with app.app_context():
    db.create_all()


# ----------------------------- 鉴权工具 -----------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        header = request.headers.get('Authorization', '')
        if header.startswith('Bearer '):
            token = header[7:]
        if not token:
            return jsonify({'message': '认证令牌缺失'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user = User.query.get(payload['user_id'])
            if not user:
                raise Exception('用户不存在')
        except Exception as e:
            return jsonify({'message': '认证失败', 'error': str(e)}), 401
        return f(user, *args, **kwargs)
    return decorated


def make_token(user_id):
    return jwt.encode(
        {'user_id': user_id, 'exp': dt.datetime.utcnow() + dt.timedelta(days=30)},
        app.config['SECRET_KEY'], algorithm="HS256")


def word_count_of(data_obj):
    """从作品 JSON 估算总字数（去掉空白），仅用于列表页展示。"""
    try:
        total = 0
        for c in data_obj.get('chapters', []):
            total += len(''.join((c.get('content') or '').split()))
        return total
    except Exception:
        return 0


# ===================== 账号（复用；前端登录地址不变） =====================
@app.route('/catcal/api/auth/register', methods=['POST'])
def register():
    d = request.get_json() or {}
    if not d.get('username') or not d.get('password'):
        return jsonify({'message': '用户名和密码为必填项'}), 400
    if User.query.filter_by(username=d['username']).first():
        return jsonify({'message': '用户名已被注册'}), 400
    u = User(username=d['username'])
    u.set_password(d['password'])
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': '注册成功', 'token': make_token(u.id),
                    'user': {'id': u.id, 'username': u.username}}), 201


@app.route('/catcal/api/auth/login', methods=['POST'])
def login():
    d = request.get_json() or {}
    u = User.query.filter_by(username=d.get('username')).first()
    if not u or not u.check_password(d.get('password', '')):
        return jsonify({'message': '用户名或密码错误'}), 401
    return jsonify({'message': '登录成功', 'token': make_token(u.id),
                    'user': {'id': u.id, 'username': u.username}}), 200


@app.route('/catcal/api/auth/me', methods=['GET'])
@token_required
def me(user):
    return jsonify({'id': user.id, 'username': user.username,
                    'created_at': user.created_at.isoformat()}), 200


# ============================= 作品 CRUD =============================
@app.route('/catcal/api/works', methods=['GET'])
@token_required
def list_works(user):
    """列出我的作品（只返回元信息，不含正文，给管理台用）"""
    works = Work.query.filter_by(user_id=user.id).order_by(Work.updated_at.desc()).all()
    return jsonify([{
        'id': w.id, 'title': w.title, 'word_count': w.word_count,
        'updated_at': w.updated_at.isoformat()
    } for w in works]), 200


@app.route('/catcal/api/works', methods=['POST'])
@token_required
def create_work(user):
    """新建作品。body = 整份作品 JSON。"""
    d = request.get_json() or {}
    wid = d.get('id') or os.urandom(8).hex()
    w = Work(id=wid, user_id=user.id, title=d.get('title', '未命名'),
             word_count=word_count_of(d), data=json.dumps(d, ensure_ascii=False))
    db.session.add(w)
    db.session.commit()
    return jsonify({'id': w.id}), 201


@app.route('/catcal/api/works/<wid>', methods=['GET'])
@token_required
def get_work(user, wid):
    """取某部作品的完整 JSON。"""
    w = Work.query.filter_by(id=wid, user_id=user.id).first()
    if not w:
        return jsonify({'message': '作品不存在'}), 404
    return app.response_class(w.data, mimetype='application/json'), 200


@app.route('/catcal/api/works/<wid>', methods=['PUT'])
@token_required
def update_work(user, wid):
    """保存/更新某部作品（前端自动保存会频繁调这里）。body = 整份作品 JSON。"""
    w = Work.query.filter_by(id=wid, user_id=user.id).first()
    if not w:
        return jsonify({'message': '作品不存在'}), 404
    d = request.get_json() or {}
    w.title = d.get('title', w.title)
    w.word_count = word_count_of(d)
    w.data = json.dumps(d, ensure_ascii=False)
    w.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'ok': True, 'updated_at': w.updated_at.isoformat()}), 200


@app.route('/catcal/api/works/<wid>', methods=['DELETE'])
@token_required
def delete_work(user, wid):
    w = Work.query.filter_by(id=wid, user_id=user.id).first()
    if not w:
        return jsonify({'message': '作品不存在'}), 404
    db.session.delete(w)
    db.session.commit()
    return jsonify({'ok': True}), 200


@app.route('/catcal/api/works/<wid>/duplicate', methods=['POST'])
@token_required
def duplicate_work(user, wid):
    """复制作品（服务端复刻一份、换新 id）。"""
    w = Work.query.filter_by(id=wid, user_id=user.id).first()
    if not w:
        return jsonify({'message': '作品不存在'}), 404
    obj = json.loads(w.data)
    new_id = os.urandom(8).hex()
    obj['id'] = new_id
    obj['title'] = (obj.get('title', '未命名') + '（副本）')
    nw = Work(id=new_id, user_id=user.id, title=obj['title'],
              word_count=w.word_count, data=json.dumps(obj, ensure_ascii=False))
    db.session.add(nw)
    db.session.commit()
    return jsonify({'id': new_id}), 201


# ===================== 可选：码字统计（跨设备日历） =====================
# 若不需要跨设备的码字日历，可把下面两个接口和上面的 Stat 类一起删掉。
@app.route('/catcal/api/stats', methods=['GET'])
@token_required
def get_stats(user):
    s = Stat.query.get(user.id)
    return app.response_class(s.data if s else '{}', mimetype='application/json'), 200


@app.route('/catcal/api/stats', methods=['PUT'])
@token_required
def put_stats(user):
    d = request.get_json() or {}
    s = Stat.query.get(user.id)
    if not s:
        s = Stat(user_id=user.id)
        db.session.add(s)
    s.data = json.dumps(d, ensure_ascii=False)
    db.session.commit()
    return jsonify({'ok': True}), 200


# ============================================================================
# ⚠️【朋友需配置 4】运行方式
#   · 本地开发：直接 python app.py（用下面这段，端口 5002）。
#   · 生产部署：用 gunicorn 跑，例如：
#         gunicorn -w 2 -b 127.0.0.1:5002 app:app
#     并保持 Nginx 把  https://qisimiaoxiang.site/catcal/  反代到  127.0.0.1:5002。
#     —— 新接口都在 /catcal/api/ 下，复用你现有的反代，无需改 Nginx。
#   · 生产务必 debug=False（下面已设为 False）。
# ============================================================================
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT', 5002)), debug=False)
