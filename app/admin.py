from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from flask_mail import Message
from functools import wraps
from datetime import datetime  # ✅ Import ajouté
from .extensions import db, mail
from .models import User, Project, Scan, Ticket, ActivityLog, ComplianceChecklist, Organization

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ✅ FILTRE JINJA2 POUR LA COULEUR DU SCORE
def score_color(score):
    """Retourne la couleur CSS en fonction du score."""
    if score is None:
        return 'none'
    if score >= 75:
        return 'green'
    elif score >= 50:
        return 'orange'
    else:
        return 'red'


# ✅ FILTRE JINJA2 POUR LE GRADE (A, B, C, D, F)
def score_grade(score):
    """Retourne le grade en fonction du score."""
    if score is None:
        return 'N/A'
    if score >= 90:
        return 'A'
    elif score >= 75:
        return 'B'
    elif score >= 60:
        return 'C'
    elif score >= 40:
        return 'D'
    else:
        return 'F'


# ✅ Enregistrement des filtres dans Jinja2
@admin_bp.app_template_filter('score_color')
def score_color_filter(score):
    return score_color(score)


@admin_bp.app_template_filter('score_grade')
def score_grade_filter(score):
    return score_grade(score)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Accès réservé aux administrateurs.', 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated


def send_account_creation_email(user, setup_url):
    try:
        msg = Message(
            subject="Vos identifiants DevShield",
            recipients=[user.email],
            sender='DevShield <devshieldlenergysmart@gmail.com>'
        )
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; background: #f5f5f9; padding: 40px 0;">
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
                        Votre compte a été créé
                    </h2>
                    <p style="color: #374151; line-height: 1.6; margin: 0 0 24px;">
                        Un compte DevShield a été créé pour vous par l'administrateur.
                        Voici vos informations de connexion :
                    </p>
                    <div style="background: #f9fafb; border: 1px solid #e5e7eb;
                                border-radius: 6px; padding: 16px 20px; margin-bottom: 24px;">
                        <div style="margin-bottom: 8px;">
                            <span style="font-size: 11px; font-weight: 700; color: #6b7280;
                                         text-transform: uppercase; letter-spacing: 0.05em;">
                                Identifiant
                            </span>
                            <div style="font-size: 16px; font-weight: 700; color: #111827;
                                        font-family: monospace; margin-top: 2px;">
                                {user.username}
                            </div>
                        </div>
                        <div>
                            <span style="font-size: 11px; font-weight: 700; color: #6b7280;
                                         text-transform: uppercase; letter-spacing: 0.05em;">
                                Rôle
                            </span>
                            <div style="font-size: 14px; color: #374151; margin-top: 2px;">
                                {user.role_label}
                            </div>
                        </div>
                    </div>
                    <p style="color: #374151; line-height: 1.6; margin: 0 0 24px;">
                        Pour des raisons de sécurité, vous devez définir votre propre
                        mot de passe en cliquant sur le bouton ci-dessous.
                        <strong>Ce lien est valable 24 heures.</strong>
                    </p>
                    <div style="text-align: center; margin-bottom: 24px;">
                        <a href="{setup_url}"
                           style="display: inline-block; background: #6366f1; color: #ffffff;
                                  font-size: 14px; font-weight: 600; padding: 12px 28px;
                                  border-radius: 6px; text-decoration: none;">
                            Définir mon mot de passe
                        </a>
                    </div>
                    <p style="font-size: 12px; color: #9ca3af; line-height: 1.6; margin: 0;">
                        Si vous n'attendiez pas cet email, ignorez-le.
                        Ce lien expirera automatiquement dans 24 heures.
                    </p>
                </div>
                <div style="background: #f9fafb; border-top: 1px solid #e5e7eb;
                            padding: 16px 32px; text-align: center;">
                    <p style="font-size: 11px; color: #9ca3af; margin: 0;">
                        DevShield — Lenergy Smart SAS |
                        Cet email a été envoyé automatiquement, ne pas répondre.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        mail.send(msg)
        return True
    except Exception as e:
        print(f'Erreur envoi email : {e}')
        return False


@admin_bp.route('/')
@login_required
@admin_required
def dashboard():
    import json
    from datetime import datetime
    
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_projects = Project.query.count()
    total_scans = Scan.query.count()
    open_tickets = Ticket.query.filter_by(status='open').count()
    resolved_tickets = Ticket.query.filter_by(status='resolved').count()
    critical_tickets = Ticket.query.filter_by(
        status='open', severity='critical'
    ).count()

    all_scans = Scan.query.filter_by(status='done').all()
    nis2_scores = []
    for scan in all_scans:
        if scan.results:
            data = json.loads(scan.results)
            if 'nis2_score' in data:
                nis2_scores.append(data['nis2_score'])
    avg_nis2 = round(sum(nis2_scores) / len(nis2_scores)) if nis2_scores else None

    all_checklists = ComplianceChecklist.query.all()
    org_scores = [c.org_score for c in all_checklists] if all_checklists else []
    avg_org_compliance = round(sum(org_scores) / len(org_scores)) if org_scores else None
    projects_without_checklist = total_projects - len(all_checklists)

    active_scan_authorized_count = Project.query.filter_by(authorized_active_scan=True).count()

    total_organizations = Organization.query.count()

    recent_logs = ActivityLog.query.order_by(
        ActivityLog.created_at.desc()
    ).limit(15).all()

    projects = Project.query.all()
    
    # Ajouter le score comme attribut temporaire
    for project in projects:
        scan = project.latest_scan
        project._security_score = scan.score if scan else None

    organizations = Organization.query.all()
    
    # ✅ Date actuelle
    now = datetime.now()

    return render_template(
        'admin/dashboard.html',
        total_users=total_users,
        active_users=active_users,
        total_projects=total_projects,
        total_scans=total_scans,
        open_tickets=open_tickets,
        resolved_tickets=resolved_tickets,
        critical_tickets=critical_tickets,
        avg_nis2=avg_nis2,
        avg_org_compliance=avg_org_compliance,
        projects_without_checklist=projects_without_checklist,
        active_scan_authorized_count=active_scan_authorized_count,
        total_organizations=total_organizations,
        recent_logs=recent_logs,
        projects=projects,
        organizations=organizations,
        now=now  # ✅ Passé au template
    )


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    organizations = Organization.query.all()
    return render_template('admin/users.html', users=all_users, organizations=organizations)


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    organizations = Organization.query.all()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        role = request.form.get('role', 'developer')
        organization_id = request.form.get('organization_id', type=int)

        if not all([username, email]):
            flash('Le nom d\'utilisateur et l\'email sont obligatoires.', 'danger')
            return render_template('admin/create_user.html', organizations=organizations)

        if User.query.filter_by(username=username).first():
            flash('Ce nom d\'utilisateur existe déjà.', 'danger')
            return render_template('admin/create_user.html', organizations=organizations)

        if User.query.filter_by(email=email).first():
            flash('Cet email est déjà utilisé.', 'danger')
            return render_template('admin/create_user.html', organizations=organizations)

        user = User(
            username=username,
            email=email,
            role=role,
            organization_id=organization_id,
            must_change_password=True
        )

        token = user.generate_setup_token()
        db.session.add(user)
        db.session.commit()

        setup_url = url_for('auth.setup_password', token=token, _external=True)

        email_sent = send_account_creation_email(user, setup_url)

        log = ActivityLog(
            user_id=current_user.id,
            action='create_user',
            details=f'Compte créé : {username} ({role}) — email {"envoyé" if email_sent else "non envoyé"}'
        )
        db.session.add(log)
        db.session.commit()

        if email_sent:
            flash(
                f'Compte "{username}" créé. Un email a été envoyé à {email} '
                f'avec le lien de configuration.',
                'success'
            )
        else:
            flash(
                f'Compte "{username}" créé mais l\'email n\'a pas pu être envoyé. '
                f'Lien de configuration : {setup_url}',
                'warning'
            )

        return redirect(url_for('admin.users'))

    return render_template('admin/create_user.html', organizations=organizations)


@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    organizations = Organization.query.all()

    if request.method == 'POST':
        new_role = request.form.get('role', user.role)
        new_active = request.form.get('is_active') == 'on'
        new_organization_id = request.form.get('organization_id', type=int)

        if user.id == current_user.id and not new_active:
            flash('Vous ne pouvez pas désactiver votre propre compte.', 'danger')
            return render_template('admin/edit_user.html', user=user, organizations=organizations)

        old_role = user.role
        user.role = new_role
        user.is_active = new_active
        user.organization_id = new_organization_id

        log = ActivityLog(
            user_id=current_user.id,
            action='edit_user',
            details=f'Modification de {user.username} : rôle {old_role} -> {new_role}'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Compte "{user.username}" mis à jour.', 'success')
        return redirect(url_for('admin.users'))

    return render_template('admin/edit_user.html', user=user, organizations=organizations)


@admin_bp.route('/users/<int:user_id>/resend', methods=['POST'])
@login_required
@admin_required
def resend_invitation(user_id):
    user = User.query.get_or_404(user_id)

    if user.password_hash and not user.must_change_password:
        flash('Cet utilisateur a déjà configuré son compte.', 'warning')
        return redirect(url_for('admin.users'))

    token = user.generate_setup_token()
    db.session.commit()

    setup_url = url_for('auth.setup_password', token=token, _external=True)
    email_sent = send_account_creation_email(user, setup_url)

    if email_sent:
        flash(f'Invitation renvoyée à {user.email}.', 'success')
    else:
        flash(f'Erreur d\'envoi. Lien : {setup_url}', 'warning')

    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('Vous ne pouvez pas supprimer votre propre compte.', 'danger')
        return redirect(url_for('admin.users'))

    username = user.username
    db.session.delete(user)

    log = ActivityLog(
        user_id=current_user.id,
        action='delete_user',
        details=f'Suppression du compte : {username}'
    )
    db.session.add(log)
    db.session.commit()

    flash(f'Compte "{username}" supprimé.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    action_filter = request.args.get('action', '')

    query = ActivityLog.query
    if search:
        query = query.filter(ActivityLog.details.ilike(f'%{search}%'))
    if action_filter:
        query = query.filter(ActivityLog.action == action_filter)

    logs = query.order_by(ActivityLog.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )

    return render_template(
        'admin/logs.html',
        logs=logs,
        search=search,
        action_filter=action_filter
    )


@admin_bp.route('/projects')
@login_required
@admin_required
def projects():
    all_projects = Project.query.order_by(Project.created_at.desc()).all()
    users_map = {u.id: u for u in User.query.all()}
    organizations = Organization.query.all()

    checklists_map = {c.project_id: c for c in ComplianceChecklist.query.all()}

    # Ajouter le score comme attribut temporaire
    for project in all_projects:
        scan = project.latest_scan
        project._security_score = scan.score if scan else None

    from app.scanner import score_to_grade, score_to_color
    return render_template(
        'admin/projects.html',
        projects=all_projects,
        users_map=users_map,
        organizations=organizations,
        checklists_map=checklists_map,
        score_to_grade=score_to_grade,
        score_to_color=score_to_color
    )


@admin_bp.route('/organizations')
@login_required
@admin_required
def organizations():
    all_organizations = Organization.query.order_by(Organization.created_at.desc()).all()
    users_map = {u.id: u for u in User.query.all()}
    return render_template(
        'admin/organizations.html',
        organizations=all_organizations,
        users_map=users_map
    )


@admin_bp.route('/organizations/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_organization():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        slug = request.form.get('slug', '').strip()
        description = request.form.get('description', '').strip()

        if not name or not slug:
            flash('Le nom et le slug sont obligatoires.', 'danger')
            return render_template('admin/create_organization.html')

        if Organization.query.filter_by(name=name).first():
            flash('Une organisation avec ce nom existe déjà.', 'danger')
            return render_template('admin/create_organization.html')

        if Organization.query.filter_by(slug=slug).first():
            flash('Une organisation avec ce slug existe déjà.', 'danger')
            return render_template('admin/create_organization.html')

        org = Organization(
            name=name,
            slug=slug,
            description=description,
            created_by=current_user.id
        )
        db.session.add(org)
        db.session.commit()

        log = ActivityLog(
            user_id=current_user.id,
            action='create_organization',
            details=f'Organisation créée : {name}'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Organisation "{name}" créée avec succès.', 'success')
        return redirect(url_for('admin.organizations'))

    return render_template('admin/create_organization.html')


@admin_bp.route('/organizations/<int:org_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_organization(org_id):
    org = Organization.query.get_or_404(org_id)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        slug = request.form.get('slug', '').strip()
        description = request.form.get('description', '').strip()
        is_active = request.form.get('is_active') == 'on'

        if not name or not slug:
            flash('Le nom et le slug sont obligatoires.', 'danger')
            return render_template('admin/edit_organization.html', org=org)

        existing_name = Organization.query.filter(
            Organization.name == name,
            Organization.id != org.id
        ).first()
        if existing_name:
            flash('Une organisation avec ce nom existe déjà.', 'danger')
            return render_template('admin/edit_organization.html', org=org)

        existing_slug = Organization.query.filter(
            Organization.slug == slug,
            Organization.id != org.id
        ).first()
        if existing_slug:
            flash('Une organisation avec ce slug existe déjà.', 'danger')
            return render_template('admin/edit_organization.html', org=org)

        org.name = name
        org.slug = slug
        org.description = description
        org.is_active = is_active

        db.session.commit()

        log = ActivityLog(
            user_id=current_user.id,
            action='edit_organization',
            details=f'Modification de l\'organisation : {name}'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Organisation "{name}" mise à jour.', 'success')
        return redirect(url_for('admin.organizations'))

    return render_template('admin/edit_organization.html', org=org)


@admin_bp.route('/organizations/<int:org_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_organization(org_id):
    org = Organization.query.get_or_404(org_id)

    user_count = User.query.filter_by(organization_id=org.id).count()
    project_count = Project.query.filter_by(organization_id=org.id).count()

    if user_count > 0 or project_count > 0:
        flash(f'Impossible de supprimer "{org.name}". Des utilisateurs ({user_count}) ou projets ({project_count}) y sont rattachés.', 'danger')
        return redirect(url_for('admin.organizations'))

    name = org.name
    db.session.delete(org)
    db.session.commit()

    log = ActivityLog(
        user_id=current_user.id,
        action='delete_organization',
        details=f'Suppression de l\'organisation : {name}'
    )
    db.session.add(log)
    db.session.commit()

    flash(f'Organisation "{name}" supprimée.', 'success')
    return redirect(url_for('admin.organizations'))