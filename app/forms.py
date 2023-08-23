from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from .models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()], render_kw={"placeholder": "email"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={
                             "placeholder": "password"})
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()], render_kw={"placeholder": "email"})

    name = StringField('Name', validators=[DataRequired(), Length(
        1, 64)], render_kw={"placeholder": "name"})
    # username = StringField('Username', validators=[
    #                        DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
    #                                                              'Usernames must have only letters, '
    #                                                              'numbers, dots or underscores')],
    #                        render_kw={"placeholder": "username"})
    password = PasswordField('Password', validators=[
                             DataRequired(), EqualTo('password2', message='Passwords must match')],
                             render_kw={"placeholder": "password"})
    password2 = PasswordField('Confirm password', validators=[DataRequired()],
                              render_kw={"placeholder": "confirm password"})
    submit = SubmitField('Register')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()], render_kw={"placeholder": "email"})
    submit = SubmitField('Reset Password')


class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[
                             DataRequired(), EqualTo('password2', message='Passwords must match')],
                             render_kw={"placeholder": "password"})
    password2 = PasswordField('Confirm password', validators=[
                              DataRequired()], render_kw={"placeholder": "confirm password"})
    submit = SubmitField('Reset Password')


class ResendConfirmationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()], render_kw={"placeholder": "email"})
    submit = SubmitField('Resend Confirmation')


class PasswordUpdateForm(FlaskForm):
    old_password = PasswordField('Current Password', validators=[
        DataRequired()])
    password = PasswordField('New password', validators=[
                             DataRequired(), EqualTo('password2', message='Passwords must match')],
                             render_kw={"placeholder": "password"})
    password2 = PasswordField('Confirm new password', validators=[
                              DataRequired()], render_kw={"placeholder": "confirm password"})
    submit = SubmitField('Update Password')


class EmailUpdateForm(FlaskForm):
    old_email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                                 Email()], render_kw={"placeholder": "current email"})
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()], render_kw={"placeholder": "new email"})
    submit = SubmitField('Update Email')

    # def validate_email(self, field):
    #     if User.query.filter_by(email=field.data).first():
    #         raise ValidationError('Email already registered.')
    #
    # def validate_username(self, field):
    #     if User.query.filter_by(username=field.data).first():
    #         raise ValidationError('Username already in use.')
