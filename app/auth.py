from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
from .models import User
from . import db
from .forms import LoginForm, RegistrationForm
import sys

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and check_password_hash(user.password, form.password.data):
            login_user(user, form.remember_me.data)

            # go to the next page if it exists, otherwise go to the profile page
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.profile')
            return redirect(next)
        flash('Invalid email or password.')

    return render_template('login.html', form=form)


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
        return redirect(url_for('auth.login'))

    return render_template('signup.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
