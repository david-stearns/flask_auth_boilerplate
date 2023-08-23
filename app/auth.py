from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, Markup
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from .models import User
from . import db
from .forms import LoginForm, RegistrationForm, PasswordResetRequestForm, PasswordResetForm, ResendConfirmationForm
from .email import send_email
import sys

auth = Blueprint('auth', __name__)


# __________ User Login and Logout __________

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user.confirmed == 0:
            flash('Please follow the link in your email to confirm your account.')
        elif user is not None and check_password_hash(user.password, form.password.data):
            login_user(user, form.remember_me.data)
            # go to the next page if it exists, otherwise go to the profile page
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.profile')
            return redirect(next)
        flash('Invalid email or password.')

    return render_template('login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


# __________ User Registration and Confirmation __________

@auth.route('/signup', methods=['GET', 'POST'])
def signup():

    form = RegistrationForm()
    if form.validate_on_submit():
        # if this returns a user, then the email already exists in database
        user = User.query.filter_by(email=form.email.data.lower()).first()

        if user:
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))

        # create a new user with the form data and hash the password
        new_user = User(email=form.email.data, name=form.name.data,
                        password=generate_password_hash(form.password.data, method='sha256'))

        db.session.add(new_user)
        db.session.commit()

        # send email to new user
        token = new_user.generate_confirmation_token()
        print(token, file=sys.stdout)

        send_email(new_user.email, "Confirm Your Account",
                   "auth/email/confirm", user=new_user, token=token)
        flash(Markup('A confirmation email has been sent. If you did not recieve a link, please click <a href="/resend_confirmation" class="alert-link">here</a> to resend'))
        return redirect(url_for('auth.login'))

    return render_template('signup.html', form=form)


@auth.route('/confirm/<token>')
def confirm(token):
    # returns user id if token is valid
    confirmed_id = User.confirm_email(token)
    # confirm account in db
    if confirmed_id:
        user = User.query.get(confirmed_id)
        user.confirmed = True
        db.session.commit()
        flash('You have confirmed your account! Please login to continue.')
        return redirect(url_for('auth.login'))
    else:
        flash(Markup('The confirmation link is invalid or has expired. Please click <a href="/resend_confirmation" class="alert-link">here</a> to resend confirmation email.'))
        return redirect(url_for('auth.login'))


@auth.route('/resend_confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    form = ResendConfirmationForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token = user.generate_confirmation_token()
            send_email(user.email, "Confirm Your Account",
                       "auth/email/confirm", user=user, token=token)
            print(email, file=sys.stdout)
            flash('A new confirmation email has been sent to ' + email)
        else:
            flash('Email address does not exist')
    return render_template('resend_confirmation.html', form=form)


# __________ User Password Reset __________

@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token)
        flash('An email with instructions to reset your password has been '
              'sent to you.')
        return redirect(url_for('auth.login'))
    return render_template('reset_password_request.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        if User.reset_password(token, generate_password_hash(form.password.data, method='sha256')):
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('reset_password.html', form=form)

# __________ User Update Email or Password __________


@auth.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    return render_template('account.html')
