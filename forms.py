# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

class RegisterForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=4, max=32)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6, max=32)])
    confirm_password = PasswordField('비밀번호 확인', validators=[DataRequired(), EqualTo('password', message='비밀번호가 일치하지 않습니다.')])
    submit = SubmitField('회원가입')

class LoginForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=4, max=32)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6, max=32)])
    submit = SubmitField('로그인')
