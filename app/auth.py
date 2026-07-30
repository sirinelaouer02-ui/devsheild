from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from datetime import datetime
from .extensions import db, mail, limiter, csrf
from .models import User, ActivityLog
import pyotp
import qrcode
from io import BytesIO
import base64
from PIL import Image

auth_bp = Blueprint('auth', __name__)


def send_reset_email(user, reset_url):
    """Envoie l'email de réinitialisation."""
    try:
        msg = Message(
            subject="Réinitialisation de votre mot de passe DevShield",
            recipients=[user.email],
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 40px 0;">
            <div style="max-width: 560px; margin: 0 auto; background: #ffffff;
                        border-radius: 8px; overflow: hidden;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <div style="background: #111827; padding: 28px 32px;">
                    <div style="font-size: 20px; font-weight: 700; color: #ffffff;">
                        DevShield
                    </div>
                    <div style="font-size: 12px; color: #6b7280; margin-top: 2px;">
                        Lenergy Smart — Plateforme DevSecOps
                    </div>
                </div>
                <div style="padding: 32px;">
                    <h2 style="font-size: 18px; color: #111827; margin: 0 0 16px;">
                        Réinitialisation du mot de passe
                    </h2>
                    <p style="color: #374151; line-height: 1.6; margin: 0 0 24px;">
                        Bonjour {user.username},<br><br>
                        Vous avez demandé à réinitialiser votre mot de passe sur la plateforme DevShield.
                        Cliquez sur le bouton ci-dessous pour définir un nouveau mot de passe :
                    </p>
                    <div style="text-align: center; margin-bottom: 24px;">
                        <a href="{reset_url}"
                           style="display: inline-block; background: #6366f1; color: #ffffff;
                                  font-size: 14px; font-weight: 600; padding: 12px 28px;
                                  border-radius: 6px; text-decoration: none;">
                            Réinitialiser mon mot de passe
                        </a>
                    </div>
                    <p style="font-size: 12px; color: #9ca3af; line-height: 1.6; margin: 0;">
                        Ce lien expire dans 1 heure.<br>
                        Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.
                    </p>
                </div>
                <div style="background: #f9fafb; border-top: 1px solid #e5e7eb;
                            padding: 16px 32px; text-align: center;">
                    <p style="font-size: 11px; color: #9ca3af; margin: 0;">
                        DevShield — Lenergy Smart SAS
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        mail.send(msg)
        print(f"✅ Email de réinitialisation envoyé à {user.email}")
        return True
    except Exception as e:
        print(f"❌ Erreur envoi email reset : {e}")
        return False


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Remplis tous les champs.', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Identifiants incorrects.', 'danger')
            return render_template('login.html')

        if not user.is_active:
            flash('Ce compte a été désactivé. Contacte un administrateur.', 'danger')
            return render_template('login.html')

        # Si 2FA activée, rediriger vers la vérification OTP
        if user.otp_enabled:
            session['otp_user_id'] = user.id
            return redirect(url_for('auth.verify_otp'))

        login_user(user, remember=True)
        log = ActivityLog(
            user_id=user.id,
            action='login',
            details=f'Connexion de {user.username}'
        )
        db.session.add(log)
        db.session.commit()

        next_page = request.args.get('next')
        return redirect(next_page or url_for('main.dashboard'))

    return render_template('login.html')


@auth_bp.route('/otp/verify', methods=['GET', 'POST'])
def verify_otp():
    """Page de vérification du code OTP (2FA)."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    user_id = session.get('otp_user_id')
    if not user_id:
        flash('Veuillez vous connecter d\'abord.', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user or not user.otp_enabled:
        flash('Configuration 2FA invalide.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        token = request.form.get('otp_token', '').strip()
        if not token:
            flash('Veuillez saisir le code à 6 chiffres.', 'danger')
            return render_template('otp_verify.html', username=user.username)

        if user.verify_otp(token):
            login_user(user, remember=True)
            session.pop('otp_user_id', None)
            log = ActivityLog(
                user_id=user.id,
                action='login',
                details=f'Connexion de {user.username} avec 2FA'
            )
            db.session.add(log)
            db.session.commit()
            flash('Authentification réussie.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('Code OTP invalide. Veuillez réessayer.', 'danger')

    return render_template('otp_verify.html', username=user.username)


@auth_bp.route('/otp/setup', methods=['GET', 'POST'])
@login_required
def setup_otp():
    """Activation ou désactivation de la 2FA."""
    user = current_user

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'enable':
            token = request.form.get('otp_token', '').strip()
            if not token:
                flash('Veuillez saisir le code à 6 chiffres.', 'danger')
            else:
                if user.verify_otp(token):
                    user.enable_otp()
                    flash('Authentification à deux facteurs activée avec succès.', 'success')
                    return redirect(url_for('main.dashboard'))
                else:
                    flash('Code OTP invalide. Veuillez réessayer.', 'danger')
        elif action == 'disable':
            user.disable_otp()
            flash('Authentification à deux facteurs désactivée.', 'info')
            return redirect(url_for('main.dashboard'))

    # Générer un nouveau secret si absent
    if not user.otp_secret:
        user.otp_secret = pyotp.random_base32()
        db.session.commit()

    otp_uri = user.get_otp_uri()

    # Générer un QR code
    try:
        qr = qrcode.make(otp_uri)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
    except TypeError:
        qr_code = qrcode.QRCode(box_size=10, border=4)
        qr_code.add_data(otp_uri)
        qr_code.make(fit=True)
        img = qr_code.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
    except Exception:
        flash('Impossible de générer le QR code. Utilisez le secret ci-dessous.', 'warning')
        return render_template('otp_setup.html',
                               otp_secret=user.otp_secret,
                               otp_enabled=user.otp_enabled,
                               qr_base64=None,
                               username=user.username)

    qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    return render_template('otp_setup.html',
                           otp_secret=user.otp_secret,
                           otp_enabled=user.otp_enabled,
                           qr_base64=qr_base64,
                           username=user.username)


@auth_bp.route('/register')
def register():
    flash('La création de compte est réservée aux administrateurs.', 'danger')
    return redirect(url_for('auth.login'))


@auth_bp.route('/setup/<token>', methods=['GET', 'POST'])
def setup_password(token):
    user = User.query.filter_by(setup_token=token).first()

    if not user:
        flash('Lien invalide ou déjà utilisé.', 'danger')
        return redirect(url_for('auth.login'))

    if user.setup_token_expires < datetime.utcnow():
        flash('Ce lien a expiré. Contacte un administrateur pour en recevoir un nouveau.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if len(password) < 8:
            flash('Le mot de passe doit faire au moins 8 caractères.', 'danger')
            return render_template('setup_password.html', token=token, username=user.username)

        if password != confirm:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return render_template('setup_password.html', token=token, username=user.username)

        user.set_password(password)
        user.setup_token = None
        user.setup_token_expires = None
        user.must_change_password = False

        log = ActivityLog(
            user_id=user.id,
            action='setup_password',
            details=f'{user.username} a défini son mot de passe'
        )
        db.session.add(log)
        db.session.commit()

        login_user(user)
        flash('Mot de passe défini. Bienvenue sur DevShield !', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('setup_password.html', token=token, username=user.username)


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        print(f"📧 Email reçu : {email}")
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.generate_reset_token()
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            print(f"🔑 Token généré : {token}")
            print(f"🔗 URL générée : {reset_url}")
            send_reset_email(user, reset_url)
        else:
            print(f"⚠️ Aucun utilisateur trouvé avec l'email : {email}")
        flash('Un email vous a été envoyé avec les instructions pour réinitialiser votre mot de passe.', 'info')
        return redirect(url_for('auth.login'))

    return render_template('reset_request.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    print(f"🔑 Token reçu : {token}")

    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    user = User.verify_reset_token(token)
    print(f"👤 Utilisateur trouvé : {user.username if user else 'Aucun'}")

    if user is None:
        flash('Ce lien est invalide ou a expiré.', 'danger')
        return redirect(url_for('auth.reset_request'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm = request.form.get('confirm_password', '').strip()

        if not password or len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères.', 'danger')
        elif password != confirm:
            flash('Les mots de passe ne correspondent pas.', 'danger')
        else:
            user.set_password(password)
            user.must_change_password = False
            db.session.commit()
            print(f"✅ Mot de passe réinitialisé pour {user.username}")
            flash('Votre mot de passe a été réinitialisé. Vous pouvez vous connecter.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)


@auth_bp.route('/logout')
@login_required
def logout():
    log = ActivityLog(
        user_id=current_user.id,
        action='logout',
        details=f'Déconnexion de {current_user.username}'
    )
    db.session.add(log)
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))