from flask import Flask, request, redirect, url_for, flash
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError
from dotenv import load_dotenv
import os
from datetime import timezone
from zoneinfo import ZoneInfo
from .models import db, User
from .extensions import csrf, limiter, login_manager, mail, migrate

load_dotenv()

PARIS_TZ = ZoneInfo("Europe/Paris")


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL', 'sqlite:///instance/devsheild.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Configuration Celery
    app.config['broker_url'] = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    app.config['result_backend'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

    # Configuration email
    app.config['MAIL_SERVER']         = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT']           = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS']        = os.getenv('MAIL_USE_TLS', 'True') == 'True'
    app.config['MAIL_USERNAME']       = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD']       = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

    # Initialisation des extensions
    db.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)  # ✅ CSRF activé pour toute l'application

    # Gestionnaire d'erreur CSRF
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        flash('Erreur de securite. Veuillez reessayer.', 'danger')
        return redirect(request.referrer or url_for('main.dashboard'))

    # Gestionnaire d'erreur rate-limiting (429)
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Trop de requêtes - DevShield</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
                    background: #f1f5f9;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                }
                .container {
                    background: #ffffff;
                    padding: 48px 40px;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
                    max-width: 480px;
                    width: 100%;
                    text-align: center;
                    border: 1px solid #e2e8f0;
                }
                .code {
                    font-size: 14px;
                    color: #94a3b8;
                    font-weight: 600;
                    letter-spacing: 1px;
                    margin-bottom: 8px;
                }
                h1 {
                    font-size: 24px;
                    font-weight: 700;
                    color: #0f172a;
                    margin: 0 0 12px 0;
                }
                .message {
                    font-size: 16px;
                    color: #475569;
                    line-height: 1.6;
                    margin: 0 0 28px 0;
                }
                .message strong {
                    color: #0f172a;
                }
                .btn {
                    display: inline-block;
                    padding: 10px 28px;
                    background: #2563eb;
                    color: #ffffff;
                    text-decoration: none;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: 600;
                    border: none;
                    cursor: pointer;
                }
                .btn:hover {
                    background: #1d4ed8;
                }
                .footer {
                    margin-top: 24px;
                    font-size: 12px;
                    color: #94a3b8;
                    border-top: 1px solid #f1f5f9;
                    padding-top: 20px;
                }
                .footer span {
                    color: #2563eb;
                    font-weight: 600;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="code">429</div>
                <h1>Trop de requêtes</h1>
                <p class="message">
                    Vous avez envoyé <strong>trop de requêtes</strong>.<br>
                    Attendez <strong>quelques minutes</strong> avant de réessayer.
                </p>
                <a href="javascript:history.back()" class="btn">Retour</a>
                <div class="footer">
                    DevShield — <span>Lenergy Smart</span>
                </div>
            </div>
        </body>
        </html>
        """, 429

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Connecte-toi pour accéder à cette page.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Filtre Jinja pour convertir une date UTC (stockée naïve) en heure de Paris
    @app.template_filter('local_time')
    def local_time_filter(dt):
        if dt is None:
            return "—"
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(PARIS_TZ).strftime('%d/%m/%Y à %H:%M')

    from .auth import auth_bp
    from .routes import main_bp
    from .admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)

    # ✅ Désactiver CSRF sur le blueprint d'authentification (pour simplifier)
    csrf.exempt(auth_bp)

    with app.app_context():
        db.create_all()

    return app