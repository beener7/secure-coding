from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import re
import uuid
from flask_sqlalchemy import SQLAlchemy

# 앱 설정
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# 사용자 테이블 모델
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# 회원가입 폼
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

# 로그인 폼
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

# 회원가입 뷰
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()

        # 사용자명과 비밀번호 유효성 검사
        if not re.match(r'^[\w.@+-]{4,20}$', username):
            flash('사용자명이 유효하지 않습니다.')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('비밀번호는 최소 6자 이상이어야 합니다.')
            return redirect(url_for('register'))

        # 사용자명 중복 체크
        user = User.query.filter_by(username=username).first()
        if user:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        # 사용자 등록
        user_id = str(uuid.uuid4())
        hashed_pw = generate_password_hash(password)
        new_user = User(id=user_id, username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# 로그인 뷰
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            flash('로그인 성공!')
            return redirect(url_for('profile'))  # 로그인 성공 후 프로필 페이지로 리다이렉트
        else:
            flash('잘못된 사용자명 또는 비밀번호입니다.')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

# 프로필 페이지
@app.route('/profile')
def profile():
    return render_template('profile.html')

if __name__ == '__main__':
    app.run(debug=True)
