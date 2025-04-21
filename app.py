from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import InputRequired, Length, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secure-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

DATABASE = 'market.db'

# 폼 정의
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(),
        Length(min=4, max=20),
        Regexp(r'^[\w.@+-]+$', message="유효한 사용자명을 입력하세요.")
    ])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class ProfileForm(FlaskForm):
    bio = TextAreaField('Bio', validators=[Length(max=300)])

class ProductForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(max=500)])
    price = StringField('Price', validators=[InputRequired(), Length(max=20)])

# 데이터베이스 연결 관리
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DATABASE)
        g._database = db
    return db

def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        db.commit()

# 회원가입 뷰
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()

        # 유효성 검사
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)", 
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# 로그인 뷰
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

        if user and check_password_hash(user[2], password):
            session.clear()  # 세션 고정 공격 방지
            session.permanent = True
            session['user_id'] = user[0]
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

# 로그아웃 뷰
@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('login'))

# 대시보드 뷰
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# 프로필 뷰
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = ProfileForm()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if form.validate_on_submit():
        bio = form.bio.data.strip()
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    form.bio.data = current_user[3] if current_user else ""
    return render_template('profile.html', user=current_user, form=form)

# 상품 등록 뷰
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = ProductForm()
    if form.validate_on_submit():
        title = form.title.data.strip()
        description = form.description.data.strip()
        price = form.price.data.strip()

        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO product (title, description, price, user_id) VALUES (?, ?, ?, ?)", 
                       (title, description, price, session['user_id']))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html', form=form)

# 신고 뷰
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = ReportForm()
    if form.validate_on_submit():
        target_id = form.target_id.data.strip()
        reason = form.reason.data.strip()

        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO report (report_id, target_id, reason) VALUES (?, ?, ?)", 
                       (report_id, target_id, reason))
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html', form=form)

if __name__ == '__main__':
    socketio = SocketIO(app)
    socketio.run(app, debug=True)
