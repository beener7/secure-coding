import sqlite3
import uuid
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secure-secret-key'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*")

DATABASE = 'market.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not re.match(r'^[\w.@+-]{4,20}$', username):
            flash('사용자명이 유효하지 않습니다.')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('비밀번호는 최소 6자 이상이어야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        hashed_pw = generate_password_hash(password)
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_pw))
        db.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            session.clear()  # 세션 고정 공격 방지
            session.permanent = True
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '').strip()
        if len(bio) > 300:
            flash('소개글은 300자 이하로 작성해주세요.')
            return redirect(url_for('profile'))
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form['price'].strip()

        if not title or not description or not price:
            flash("모든 항목을 입력해주세요.")
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id'].strip()
        reason = request.form['reason'].strip()
        if not target_id or not reason:
            flash('신고 대상과 사유를 입력해주세요.')
            return redirect(url_for('report'))
        if len(reason) > 500:
            flash('신고 사유는 500자 이하로 작성해주세요.')
            return redirect(url_for('report'))
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
