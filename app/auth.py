from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, Markup
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from .models import User
from . import db
from .forms import LoginForm, RegistrationForm, PasswordResetRequestForm, PasswordResetForm, ResendConfirmationForm, PasswordUpdateForm, EmailUpdateForm
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
        elif user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            # go to the next page if it exists, otherwise go to the profile page
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.profile')
            return redirect(next)
        flash(Markup(
            'Invalid email or password. <a href="/reset" class="alert-link">Forgot Password?</a>'))

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
                        password=form.password.data)

        db.session.add(new_user)
        db.session.commit()

        # send email to new user
        token = new_user.generate_confirmation_token()

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
            flash('A new confirmation email has been sent to ' + email)
        else:
            flash('Email address does not exist')
    return render_template('resend_confirmation.html', form=form)


# __________ User Forgot Password __________

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
        if User.reset_password(token, form.password.data):
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
    return render_template('account.html', name=current_user.name, email=current_user.email)


@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = PasswordUpdateForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.commit()
            flash('Your password has been updated.', 'success')
            return redirect(url_for('auth.account'))
        else:
            flash('Invalid password.', 'error')
        return redirect(url_for('auth.change_password'))
    elif form.submit2.data:
        for _, errors in form.errors.items():
            for error in errors:
                flash(error, 'password_error')
    return render_template('change_password.html', form=form)


@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    form = EmailUpdateForm()

    if form.validate_on_submit():
        # verify password
        if current_user.verify_password(form.password.data):
            # check to see if new email address in already in the db
            user = User.query.filter_by(
                email=form.email.data.lower()).first()
            if user:
                flash('Email address already exists', 'error')
                return redirect(url_for('auth.change_email'))
            else:
                current_user.email = form.email.data
                db.session.commit()
                flash('Your email address has been updated.', 'success')
                return redirect(url_for('auth.account'))
        else:
            flash('Invalid password.', 'email_error')
        return redirect(url_for('auth.change_email'))
    elif form.submit1.data:
        for _, errors in form.errors.items():
            for error in errors:
                flash(error, 'email_error')

    return render_template('change_email.html', form=form)
