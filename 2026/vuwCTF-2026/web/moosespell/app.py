import os
import re
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import Flask, jsonify, make_response, redirect, render_template, request
from flask_sqlalchemy import SQLAlchemy
from selenium import webdriver
from selenium.webdriver.common.by import By
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()

app = Flask(__name__)

app.config['ADMIN_PASSWORD'] = os.environ['ADMIN_PASSWORD']
app.config['FLAG'] = os.environ['FLAG']
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


class User(db.Model):
    id = db.Column(db.String(50), unique=True, nullable=False, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    admin = db.Column(db.Boolean, default=False)


class Spell(db.Model):
    id = db.Column(db.String(50), unique=True, nullable=False, primary_key=True)
    author = db.Column(db.String(120), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    incantation = db.Column(db.String(4096), nullable=False)


with app.app_context():
    db.create_all()
    if not User.query.filter_by(name='Archmage Moose').first():
        db.session.add(User(
            id=str(uuid.uuid4()),
            name='Archmage Moose',
            password=generate_password_hash(app.config['ADMIN_PASSWORD']),
            admin=True,
        ))

        db.session.add(Spell(
            id=str(uuid.uuid4()),
            author='Archmage Moose',
            title='The Forbidden Bugle',
            incantation=app.config['FLAG'],
        ))
        db.session.commit()


@app.after_request
def cast_ward(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:"
    )
    return response


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt_token')
        if not token:
            return redirect('/login')
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['id']).first()
            if current_user is None:
                return redirect('/login')
        except Exception:
            return redirect('/login')
        return f(current_user, *args, **kwargs)
    return decorated


def issue_token(user):
    return jwt.encode({
        'id': user.id,
        'username': user.name,
        'exp': datetime.utcnow() + timedelta(minutes=30),
    }, app.config['SECRET_KEY'], algorithm='HS256')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.json or {}
        name = data.get('username')
        password = data.get('password')
        if not name or not password:
            return make_response(jsonify({'message': 'Missing fields'}), 400)

        if User.query.filter_by(name=name).first():
            return make_response(jsonify({'message': 'User already exists. Please log in.'}), 202)

        user_id = str(uuid.uuid4())
        while User.query.filter_by(id=user_id).first():
            user_id = str(uuid.uuid4())

        user = User(
            id=user_id,
            name=name,
            password=generate_password_hash(password),
            admin=False,
        )
        db.session.add(user)
        db.session.commit()
        return make_response(jsonify({'message': 'Young moose registered'}), 201)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        auth = request.json or {}
        name = auth.get('username')
        password = auth.get('password')
        if not name or not password:
            return make_response(jsonify({'message': 'Could not verify'}), 401)

        user = User.query.filter_by(name=name).first()
        if not user or not check_password_hash(user.password, password):
            return make_response(jsonify({'message': 'Login unsuccessful'}), 401)

        token = issue_token(user)
        response = make_response(jsonify({'message': 'Login successful'}), 201)
        response.set_cookie('jwt_token', token, httponly=True, samesite='Lax')
        return response

    return render_template('login.html')


def sanitize(text):
    return re.sub(r'<\s*script', '', text, flags=re.IGNORECASE)


@app.route('/spells', methods=['GET', 'POST'])
@token_required
def spells(current_user):
    if request.method == 'POST':
        data = request.json or {}
        title = data.get('title', 'Untitled')
        incantation = data.get('incantation', '')

        spell_id = str(uuid.uuid4())
        while Spell.query.filter_by(id=spell_id).first():
            spell_id = str(uuid.uuid4())

        spell = Spell(
            id=spell_id,
            author=current_user.name,
            title=sanitize(title),
            incantation=sanitize(incantation),
        )
        db.session.add(spell)
        db.session.commit()
        return make_response(jsonify({'message': 'Spell inscribed',
                                      'id': spell.id}), 201)

    my_spells = Spell.query.filter_by(author=current_user.name).all()
    return render_template('spells.html', spells=my_spells)


@app.route('/spells/<spell_id>')
@token_required
def view_spell(current_user, spell_id):
    spell = Spell.query.filter_by(id=spell_id).first()
    if spell is None:
        return make_response(jsonify({'message': 'No such spell'}), 404)

    if spell.author != current_user.name and not current_user.admin:
        return make_response(jsonify({'message': 'This spell is not yours to read'}), 403)

    return render_template('spell.html', spell=spell)
    

@app.route('/report', methods=['POST'])
@token_required
def report(current_user):
    data = request.json or {}
    spell_id = data.get('spell_id')
    if not spell_id or not re.fullmatch(r'[A-Za-z0-9\-]+', str(spell_id)):
        return make_response(jsonify({'message': 'Invalid spell id'}), 400)

    DRIVER_PATH = '/app/chromedriver-linux64/chromedriver'
    CHROME_BIN = '/app/chrome-linux64/chrome'

    options = webdriver.ChromeOptions()
    options.binary_location = CHROME_BIN
    for arg in ('headless', 'no-sandbox', 'disable-dev-shm-usage',
                'disable-gpu', 'disable-extensions', 'no-first-run'):
        options.add_argument(arg)

    service = webdriver.ChromeService(DRIVER_PATH)
    driver = webdriver.Chrome(options=options, service=service)
    try:
        driver.get('http://127.0.0.1:1337/login')
        driver.find_element(By.ID, 'username').send_keys('Archmage Moose')
        driver.find_element(By.ID, 'password').send_keys(app.config['ADMIN_PASSWORD'])
        driver.find_element(By.ID, 'submit').click()
        time.sleep(2)
        driver.get(f'http://127.0.0.1:1337/spells/{spell_id}')
        time.sleep(5)
    finally:
        driver.quit()

    return make_response(jsonify({'message': 'The Archmage Moose has reviewed your spell'}), 201)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337, threaded=True, debug=False)
