import hashlib
import json
import logging
import re
import socket
import time
from email.mime.text import MIMEText
import random
from typing import Dict

from cachetools import TTLCache
from flask import Flask, render_template, request, abort, make_response, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import BaseModel

import db
from config import GLOBAL_CONFIG
from util import send_email

APP = Flask(__name__)
LIMITER = Limiter(APP, key_func=get_remote_address)


class AppSession(BaseModel):
    email: str
    timestamp: float


APP_SESSION: Dict[str, AppSession] = dict()
COOKIE_KEY = 'EMAILSUBSCRIPTIONSYSTEMCLIENTID'
REGISTER_CACHE = TTLCache(GLOBAL_CONFIG.get('app.register.cache.size', 1000),
                          GLOBAL_CONFIG.get('app.register.cache.ttl', 10 * 60))


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception as e:
        logging.error(f'Get ip from dns failed, error: {e}. It will use 127.0.0.1 for local ip.')
        return '127.0.0.1'
    finally:
        s.close()
    return ip


def check_login() -> str:
    client_id = request.cookies.get(COOKIE_KEY)
    if client_id:
        s = APP_SESSION.get(client_id)
        if s is None:
            return ''
        now = time.time()
        expire = GLOBAL_CONFIG.get('app.cookie.expire', 86400)
        if s.timestamp + expire < now:
            APP_SESSION.pop(client_id)
            return ''
        return s.email
    return ''


def pwd_hash(password: str) -> str:
    return hashlib.sha1(password.encode('utf-8')).hexdigest()


def set_login_status(email: str) -> Response:
    client_id = hashlib.sha1(f'{random.random()}{time.time()}{email}'.encode('utf-8')).hexdigest()
    response = make_response('success')
    response.set_cookie(COOKIE_KEY, client_id)
    APP_SESSION[client_id] = AppSession(email=email, timestamp=time.time())
    return response


@APP.route('/api/subscribe', methods=['POST'])
def subscribe():
    email = check_login()
    if email:
        with db.session() as s:
            user = s.query(db.User).filter(db.User.email == email).first()
            user.subscribe = 1 - user.subscribe
        return ''
    abort(400)


@APP.route('/verify', methods=['GET'])
def verify():
    key = request.args.get('key', '')
    ok = True
    try:
        user = REGISTER_CACHE.__getitem__(key)
        REGISTER_CACHE.pop(key)
        with db.session() as s:
            s.add(user)
        set_login_status(user.email)
    except KeyError:
        ok = False
    return render_template('verify.jinja2', ok=ok)


def api_register(email: str, password: str):
    with db.session() as s:
        rand = random.randrange(0, s.query(db.Sender).count())
        sender = s.query(db.Sender)[rand]
    name = GLOBAL_CONFIG.get('project.name', 'Project Name')
    host = GLOBAL_CONFIG.get('server.host', get_local_ip())
    port = GLOBAL_CONFIG.get('server.port', 50052)
    key = hashlib.sha1(f'{email}{time.time()}{random.random()}'.encode('utf-8')).hexdigest()
    REGISTER_CACHE.__setitem__(key, db.User(email=email, pwd=pwd_hash(password)))
    mail = MIMEText('\n'.join([
        f'Hi {email},',
        f'Thanks for registering {name}. Please verify your email address by clicking the URL below.',
        f'http://{host}:{port}/verify?key={key}'
    ]), 'plain', 'utf-8')
    mail['Subject'] = f'[{name}] Please confirm your email address'
    send_email(sender, [email], mail)


@APP.route('/api/login', methods=['POST'])
@LIMITER.limit('25/day')
def api_login():
    email = request.json.get('email', '')
    password = request.json.get('password', '')
    if email == '' or password == '':
        abort(400, 'email or password is empty')
    if not re.search(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email):
        abort(400, 'email is not a correct address')
    if email == GLOBAL_CONFIG.get('admin.email'):
        if password == GLOBAL_CONFIG.get('admin.password'):
            return set_login_status(email)
        abort(400)
    with db.session() as s:
        user = s.query(db.User).filter(db.User.email == email).first()
        if user and pwd_hash(password) == user.pwd:
            return set_login_status(email)
        elif user and pwd_hash(password) != user.pwd:
            abort(400, 'email or password is invalid')
    api_register(email, password)
    return Response('', status=202, mimetype='application/json')


def admin_checker():
    if check_login() != GLOBAL_CONFIG.get('admin.email'):
        abort(400)


@APP.route('/api/delete-sender', methods=['POST'])
def api_delete_sender():
    admin_checker()
    email = request.json.get('email')
    with db.session() as s:
        sender = s.query(db.Sender).filter(db.Sender.email == email).first()
        s.delete(sender)
    return ''


@APP.route('/api/add-sender', methods=['POST'])
def api_add_sender():
    admin_checker()
    sender = db.Sender(
        email=request.json.get('email'),
        pwd=request.json.get('password'),
        smtp_server=request.json.get('smtp_server'),
        smtp_port=request.json.get('smtp_port'),
    )
    if not re.search(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', sender.email):
        abort(400, 'email is not a correct address')
    with db.session() as s:
        s.add(sender)
    return ''


def admin():
    admin_checker()
    with db.session() as s:
        sender = s.query(db.Sender).all()
    kwargs = {
        'title': 'Sender Manager',
        'sender': sender,
    }
    return render_template('admin.jinja2', **kwargs)


@APP.route('/', methods=['GET'])
def index():
    email = check_login()
    kwargs = {
        "title": 'Email subscription system - index',
        "email": email,
    }
    if email:
        if email == GLOBAL_CONFIG.get('admin.email'):
            return admin()
        with db.session() as s:
            user = s.query(db.User).filter(db.User.email == email).first()
            ss = user.subscribe
        kwargs.update({
            'checked': 'checked' if ss else '',
        })
    return render_template('index.jinja2', **kwargs)


@APP.route('/login', methods=['GET'])
def login():
    email = check_login()
    kwargs = {
        "title": 'Email subscription system - login',
        "email": email,
    }
    return render_template('login.jinja2', **kwargs)


@APP.route('/register')
def register():
    return render_template('register.jinja2', title='Email subscription system - register')


@APP.route('/api/subscriber', methods=['GET'])
def api_subscriber():
    if check_login() == GLOBAL_CONFIG.get('admin.email'):
        return json.dumps(db.all_subscriber())
    abort(400)


if __name__ == '__main__':
    HOST = GLOBAL_CONFIG.get('server.host', get_local_ip())
    PORT = GLOBAL_CONFIG.get('server.port', 50052)
    DEBUG = GLOBAL_CONFIG.get('server.debug', False)
    APP.run(HOST, PORT, DEBUG)
