import os
import logging
import random
import string
from datetime import datetime, timedelta

import click
from flask import Flask, request, jsonify, redirect, abort, Blueprint, session, url_for, current_app
from flask.cli import with_appcontext
from flask_apscheduler import APScheduler
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
)
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_caching import Cache
from flasgger import Swagger, swag_from
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------
# Конфиг
# ---------------------------
# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Инициализация расширений
db = SQLAlchemy()
cache = Cache()  # Используем in-memory кэш (SimpleCache)


class Config:
    SCHEDULER_API_ENABLED = True


# ---------------------------
# Модели
# ---------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)  # Флаг суперпользователя
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f'<User {self.username}>'


class Link(db.Model):
    __tablename__ = 'links'
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.Text, nullable=False, index=True)
    short_code = db.Column(db.String(20), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    last_used_at = db.Column(db.DateTime, nullable=True, index=True)
    visit_count = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref=db.backref('links', lazy=True))

    @property
    def creator(self) -> str:
        return self.user.username if self.user else "Anonymous"

    def __repr__(self) -> str:
        return f'<Link {self.short_code}>'


# ---------------------------
# Вспомогательные функции
# ---------------------------
def generate_short_code(length: int = 6) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# ---------------------------
# Blueprint для аутентификации API
# ---------------------------
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string'},
                'password': {'type': 'string'}
            },
            'required': ['username', 'password']
        }
    }],
    'responses': {
        201: {'description': 'User registered successfully'},
        400: {'description': 'Invalid input or user already exists'}
    }
})
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "username and password required"}), 400

    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    logger.info(f"User registered: {username}")
    return jsonify({"message": "User registered successfully"}), 201


@auth_bp.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string'},
                'password': {'type': 'string'}
            },
            'required': ['username', 'password']
        }
    }],
    'responses': {
        200: {'description': 'Login successful, returns access token'},
        400: {'description': 'Invalid input'},
        401: {'description': 'Invalid credentials'}
    }
})
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "username and password required"}), 400

    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=user.id)
    logger.info(f"User logged in: {username}")
    return jsonify({"access_token": access_token}), 200


# ---------------------------
# Blueprint для работы со ссылками (API)
# ---------------------------
links_bp = Blueprint('links', __name__, url_prefix='/links')


@links_bp.route('/shorten', methods=['POST'])
@swag_from({
    'tags': ['Links'],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'original_url': {'type': 'string'},
                'custom_alias': {'type': 'string'},
                'expires_at': {'type': 'string', 'example': '2025-12-31 23:59'}
            },
            'required': ['original_url']
        }
    }],
    'responses': {
        201: {'description': 'Link created successfully'},
        400: {'description': 'Invalid input or custom alias exists'}
    }
})
def shorten():
    data = request.get_json()
    if not data or 'original_url' not in data:
        return jsonify({"error": "original_url is required"}), 400

    original_url = data['original_url']
    custom_alias = data.get('custom_alias')
    expires_at_str = data.get('expires_at')

    if custom_alias:
        if Link.query.filter_by(short_code=custom_alias).first():
            return jsonify({"error": "custom_alias already exists"}), 400
        short_code = custom_alias
    else:
        short_code = generate_short_code()
        while Link.query.filter_by(short_code=short_code).first() is not None:
            short_code = generate_short_code()

    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M')
        except ValueError:
            return jsonify({"error": "expires_at must be in format YYYY-MM-DD HH:MM"}), 400

    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
    except Exception as e:
        logger.warning("Invalid or missing token; proceeding as anonymous.")

    link = Link(
        original_url=original_url,
        short_code=short_code,
        expires_at=expires_at,
        user_id=user_id
    )
    db.session.add(link)
    db.session.commit()
    logger.info(f"Link created: {short_code} -> {original_url}")
    return jsonify({
        "short_code": short_code,
        "original_url": original_url,
        "created_by": link.creator
    }), 201


@links_bp.route('/<short_code>/stats', methods=['GET'])
@swag_from({
    'tags': ['Links'],
    'parameters': [
        {
            'name': 'short_code',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'Код короткой ссылки',
            'default': 'abc123'
        }
    ],
    'responses': {
        200: {'description': 'Link statistics retrieved successfully'},
        404: {'description': 'Link not found'}
    }
})
@cache.cached(timeout=60, query_string=True)
def stats(short_code: str):
    link = Link.query.filter_by(short_code=short_code).first()
    if not link:
        return jsonify({"error": "Link not found"}), 404

    stats = {
        "original_url": link.original_url,
        "created_at": link.created_at.isoformat(),
        "expires_at": link.expires_at.isoformat() if link.expires_at else None,
        "last_used_at": link.last_used_at.isoformat() if link.last_used_at else None,
        "visit_count": link.visit_count,
        "created_by": link.creator
    }
    return jsonify(stats), 200


@links_bp.route('/<short_code>', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['Links'],
    'parameters': [
        {
            'name': 'short_code',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'Link short code'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'original_url': {'type': 'string'}
                },
                'required': ['original_url']
            }
        }
    ],
    'responses': {
        200: {'description': 'Link updated successfully'},
        400: {'description': 'Invalid input'},
        403: {'description': 'Unauthorized'},
        404: {'description': 'Link not found'}
    }
})
def update_link(short_code: str):
    current_user_id = get_jwt_identity()
    link = Link.query.filter_by(short_code=short_code).first()
    if not link:
        return jsonify({"error": "Link not found"}), 404

    if link.user_id != current_user_id:
        return jsonify({"error": "Unauthorized to update this link"}), 403

    data = request.get_json()
    new_url = data.get('original_url')
    if not new_url:
        return jsonify({"error": "original_url is required"}), 400

    link.original_url = new_url
    db.session.commit()
    logger.info(f"Link updated: {short_code} by user {current_user_id}")
    cache.delete_memoized(stats, short_code)
    return jsonify({"message": "Link updated successfully"}), 200


@links_bp.route('/<short_code>', methods=['DELETE'])
@jwt_required()
@swag_from({
    'tags': ['Links'],
    'parameters': [
        {
            'name': 'short_code',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'Link short code'
        }
    ],
    'responses': {
        200: {'description': 'Link deleted successfully'},
        403: {'description': 'Unauthorized'},
        404: {'description': 'Link not found'}
    }
})
def delete_link(short_code: str):
    current_user_id = get_jwt_identity()
    link = Link.query.filter_by(short_code=short_code).first()
    if not link:
        return jsonify({"error": "Link not found"}), 404

    if link.user_id != current_user_id:
        return jsonify({"error": "Unauthorized to delete this link"}), 403

    db.session.delete(link)
    db.session.commit()
    logger.info(f"Link deleted: {short_code} by user {current_user_id}")
    cache.delete_memoized(stats, short_code)
    return jsonify({"message": "Link deleted successfully"}), 200


@links_bp.route('/search', methods=['GET'])
@swag_from({
    'tags': ['Links'],
    'parameters': [{
        'name': 'original_url',
        'in': 'query',
        'type': 'string',
        'required': True,
        'description': 'Original URL to search'
    }],
    'responses': {
        200: {'description': 'Link found'},
        400: {'description': 'Missing parameter'},
        404: {'description': 'Link not found'}
    }
})
def search_link():
    original_url = request.args.get('original_url')
    if not original_url:
        return jsonify({"error": "original_url parameter is required"}), 400

    link = Link.query.filter_by(original_url=original_url).first()
    if not link:
        return jsonify({"error": "Link not found"}), 404

    return jsonify({"short_code": link.short_code, "original_url": link.original_url}), 200


# Кастомизация Flask-Admin для защиты админки
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not self.is_accessible():
            return redirect(url_for('admin_bp.admin_login', next=request.url))
        return super().index()

    def is_accessible(self):
        admin_user_id = session.get('admin_user_id')
        if admin_user_id:
            user = User.query.get(admin_user_id)
            return user and user.is_admin
        return False

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_bp.admin_login', next=request.url))


class AdminModelView(ModelView):
    def is_accessible(self):
        admin_user_id = session.get('admin_user_id')
        if admin_user_id:
            user = User.query.get(admin_user_id)
            return user and user.is_admin
        return False

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_bp.admin_login', next=request.url))


class LinkAdminView(AdminModelView):
    # Исключаем свойство creator из формы, чтобы Flask не пыталчя его обрабатывать
    form_excluded_columns = ('creator',)


# Отдельный blueprint для админки (с логином)
admin_bp = Blueprint('admin_bp', __name__)


@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_admin:
            session['admin_user_id'] = user.id
            return redirect(url_for('admin.index'))
        return "Invalid credentials or not an admin", 403
    return '''
    <form method="post">
        <input type="text" name="username" placeholder="username"/>
        <input type="password" name="password" placeholder="password"/>
        <input type="submit" value="Login"/>
    </form>
    '''


# Фабрика приложения
def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv('SECRET_KEY', 'super-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///links.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['CACHE_TYPE'] = 'SimpleCache'
    app.config['CACHE_DEFAULT_TIMEOUT'] = 300
    app.config.from_object(Config)

    db.init_app(app)
    JWTManager(app)
    Swagger(app, template={
        "swagger": "2.0",
        "info": {
            "title": "Link Shortener API",
            "description": "API-сервис для сокращения ссылок",
            "version": "1.0.0"
        },
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "Введите JWT токен в формате: Bearer {your token}"
            }
        },
        "security": [
            {"Bearer": []}
        ]
    })
    cache.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(links_bp)
    app.register_blueprint(admin_bp)

    @app.route('/<short_code>')
    @swag_from({
        'tags': ['Redirect'],
        'parameters': [{
            'name': 'short_code',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'Link short code'
        }],
        'responses': {
            302: {'description': 'Redirect to original URL'},
            404: {'description': 'Link not found'},
            410: {'description': 'Link expired'}
        }
    })
    def redirect_short_code(short_code: str):
        link = Link.query.filter_by(short_code=short_code).first()
        if not link:
            abort(404)
        if link.expires_at and link.expires_at < datetime.utcnow():
            return jsonify({"error": "Link has expired"}), 410
        link.visit_count += 1
        link.last_used_at = datetime.utcnow()
        db.session.commit()
        return redirect(link.original_url)

    admin = Admin(app, name='Link Shortener Admin', template_mode='bootstrap3',
                  index_view=MyAdminIndexView(), url='/admin')
    admin.add_view(AdminModelView(User, db.session))
    admin.add_view(LinkAdminView(Link, db.session))

    with app.app_context():
        db.create_all()
        logger.info("Database tables created.")

    def delete_expired_links():
        with app.app_context():
            now = datetime.utcnow()
            expired_links = Link.query.filter(Link.expires_at != None, Link.expires_at < now).all()
            count = len(expired_links)
            for link in expired_links:
                db.session.delete(link)
            db.session.commit()
            logger.info(f"Deleted {count} expired links.")

    # Инициализация планировщика и добавление задачи
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()
    scheduler.add_job(id='Delete expired links',
                      func=delete_expired_links,
                      trigger='interval',
                      seconds=60)  # каждые 60 секунд

    logger.info("Application initialized successfully")
    return app


@click.command(name='create_superuser')
@with_appcontext
def create_superuser():
    """Создание суперпользователя для административной панели"""
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")

    if User.query.filter_by(username=username).first():
        click.echo("Пользователь с таким именем уже существует!")
        return

    user = User(username=username, is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo("Суперпользователь успешно создан.")


app = create_app()
app.cli.add_command(create_superuser)

if __name__ == '__main__':
    app.run(debug=True)
