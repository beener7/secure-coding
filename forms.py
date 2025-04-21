# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class LoginForm(FlaskForm):
    username = StringField('사용자명', validators=[DataRequired(), Length(min=4, max=32)])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6, max=32)])
    submit = SubmitField('로그인')
