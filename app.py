import sqlite3
import uuid
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from wtforms import StringField, PasswordField, SubmitField, DecimalField, TextAreaField
from flask_socketio import SocketIO, send
from flask_wtf import CSRFProtect, FlaskForm
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask import abort
from wtforms import IntegerField



# === 폼 클래스 정의 ===

class TransferForm(FlaskForm):
    amount = IntegerField('송금액', validators=[DataRequired(), NumberRange(min=1, message="금액은 1 이상이어야 합니다.")])
    submit = SubmitField('송금')


class ReportForm(FlaskForm):
    target_id = StringField('신고 대상 ID', validators=[DataRequired(), Length(min=5, max=36)])
    reason = StringField('신고 사유', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('신고하기')

class ProfileForm(FlaskForm):
    bio = TextAreaField('소개글', validators=[Length(max=300)])
    submit = SubmitField('수정하기')


class ProductForm(FlaskForm):
    title = StringField('상품명', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('설명', validators=[DataRequired(), Length(max=1000)])
    price = DecimalField('가격', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('등록')


class RegisterForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=4, max=32)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6, max=32)])
    confirm_password = PasswordField('비밀번호 확인', validators=[DataRequired(), EqualTo('password', message='비밀번호가 일치하지 않습니다.')])
    submit = SubmitField('회원가입')

class LoginForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=4, max=32)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6, max=32)])
    submit = SubmitField('로그인')

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
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            );
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            );
        """)
        db.commit()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/admin/manage_products')
def manage_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    return render_template('manage_products.html', products=products)


@app.route('/admin')
def admin_dashboard():
    # 관리자 권한 검사 부분을 제거하고, 로그인된 사용자에게 대시보드를 표시
    if 'user_id' not in session:
        return redirect(url_for('login'))  # 로그인되지 않은 경우 로그인 페이지로 리디렉션

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 관리자 검사 기능을 제외한 간단한 관리 대시보드
    return render_template('admin_dashboard.html', user=current_user)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 유저 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    sender = cursor.fetchone()

    # 송금 폼
    form = TransferForm()

    if form.validate_on_submit():
        receiver_username = request.form['receiver_username']  # 수신자 사용자명

        # 수신자 정보 가져오기
        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()

        if not receiver:
            flash("존재하지 않는 사용자입니다.")
            return redirect(url_for('transfer'))

        transfer_amount = form.amount.data

        # 송금할 금액이 충분한지 확인
        if sender['balance'] < transfer_amount:
            flash("잔액이 부족합니다.")
            return redirect(url_for('transfer'))

        # 송금 처리
        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (transfer_amount, sender['id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (transfer_amount, receiver['id']))

        # 트랜잭션을 커밋하여 변경사항을 저장
        db.commit()

        flash(f"{receiver_username}에게 {transfer_amount}원이 송금되었습니다.")
        return redirect(url_for('dashboard'))

    return render_template('transfer.html', form=form)



#@app.route('/admin')
#def admin_dashboard():

#    db = get_db()
 #  cursor.execute("SELECT * FROM user")
 #   users = cursor.fetchall()
 #   cursor.execute("SELECT * FROM product")
 #   products = cursor.fetchall()
 #   cursor.execute("SELECT * FROM report")
 #   reports = cursor.fetchall()

  #  return render_template('admin_dashboard.html', users=users, products=products, reports=reports)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()

        # 사용자명 유효성 검사
        if not re.match(r'^[\w.@+-]{4,20}$', username):
            flash('사용자명이 유효하지 않습니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 길이 검사
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

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

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

    # 현재 사용자 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 검색어 가져오기
    query = request.args.get('query', '').strip()

    if query:
        # 검색어가 있을 경우 제목에서 LIKE 검색
        cursor.execute("SELECT * FROM product WHERE title LIKE ?", ('%' + query + '%',))
    else:
        # 검색어가 없을 경우 전체 상품 조회
        cursor.execute("SELECT * FROM product")

    all_products = cursor.fetchall()

    return render_template('dashboard.html', products=all_products, user=current_user)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    form = ProfileForm(bio=current_user['bio'])

    if form.validate_on_submit():
        bio = form.bio.data.strip()
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    return render_template('profile.html', form=form)


@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = ProductForm()
    if form.validate_on_submit():
        title = form.title.data.strip()
        description = form.description.data.strip()
        price = str(form.price.data)

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

    return render_template('new_product.html', form=form)

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

@app.route('/admin/view_users')
def view_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 사용자 정보를 가져오는 로직 추가 (실제 데이터베이스 쿼리 필요)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()

    return render_template('view_users.html', users=users)



@app.route('/admin/view_reports')
def view_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 예시로 신고된 콘텐츠를 가져오는 로직 추가 (실제 데이터베이스 쿼리 필요)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM reports")
    reports = cursor.fetchall()

    return render_template('view_reports.html', reports=reports)


@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = ReportForm()

    if form.validate_on_submit():
        target_id = form.target_id.data.strip()
        reason = form.reason.data.strip()

        # 신고 대상 ID 및 사유가 유효한지 확인
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
    
    return render_template('report.html', form=form)

@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
