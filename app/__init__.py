from flask import Flask
from flask_migrate import Migrate
from app.models import db
from flask_login import LoginManager
from flask_mail import Mail, Message
from .assets import compile_static_assets
import os

migrate = Migrate()
mail = Mail()


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'SQlALCHEMY_DATABASE_URI')

    db.init_app(app)

    # flask-migrate
    migrate.init_app(app, db)

    # flask-login
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    # flask-assets
    compile_static_assets(app)

    # Flask-Mail configurations
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
    app.config['MAIL_PORT'] = os.environ.get('MAIL_PORT')
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS')

    mail.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is the primary key
        return User.query.get(int(user_id))

    # blueprint for auth routes
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth routes
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # @app.route('/send_mail')
    # def send_sample_mail():
    #     msg = Message("Hello", sender=app.config['MAIL_USERNAME'], recipients=[
    #                   "dstearns77@gmail.com"])
    #     msg.body = "This is a test email sent from a Flask app."
    #     mail.send(msg)
    #     return "Mail sent!"

    return app


application = create_app()

if __name__ == '__main__':
    application.run()
