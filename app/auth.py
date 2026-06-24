from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from .models import db, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
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
        
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            flash(f'Bienvenue {user.username} !', 'success')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            flash('Identifiants incorrects.', 'danger')
    
    return render_template('login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        # Validations
        if not all([username, email, password, confirm]):
            flash('Remplis tous les champs.', 'danger')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Le nom d\'utilisateur doit faire au moins 3 caractères.', 'danger')
            return render_template('register.html')
        
        if password != confirm:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Le mot de passe doit faire au moins 8 caractères.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Ce nom d\'utilisateur est déjà pris.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Cet email est déjà utilisé.', 'danger')
            return render_template('register.html')
        
        # Création de l'utilisateur
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Compte créé ! Tu peux maintenant te connecter.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Tu as été déconnecté.', 'info')
    return redirect(url_for('auth.login'))