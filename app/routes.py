from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response, jsonify, current_app
from flask_login import login_required, current_user
import json
from datetime import datetime

from .models import db, Project, Scan, Ticket, User, ActivityLog, ProjectMember, TicketAssignment
from .scanner import (analyze_url, score_to_grade, score_to_color,
                      nis2_status_label, nis2_status_color)
from .organization import filter_by_organization, get_current_user_organization
from app import limiter
from app.models import DomainVerification

from app.models import ScheduledScan
main_bp = Blueprint('main', __name__)


def send_project_invitation_email(user, project, inviter):
    """Envoie un email à un utilisateur ajouté à un projet."""
    from flask_mail import Message
    from app import mail
    try:
        msg = Message(
            subject=f"Vous avez été ajouté au projet {project.name}",
            recipients=[user.email],
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 40px;">
            <div style="max-width: 560px; margin: 0 auto; background: #ffffff; border-radius: 8px; padding: 32px;">
                <h2 style="color: #111827;">Ajout au projet</h2>
                <p>Bonjour {user.username},</p>
                <p>Vous avez été ajouté au projet <strong>"{project.name}"</strong> par {inviter.username}.</p>
                <p>Vous pouvez maintenant accéder à ce projet sur DevShield.</p>
                <p><a href="{url_for('main.project_detail', project_id=project.id, _external=True)}" style="background: #4f8cff; color: #fff; padding: 10px 20px; border-radius: 6px; text-decoration: none;">Voir le projet</a></p>
                <p style="font-size: 12px; color: #9ca3af;">DevShield — Lenergy Smart SAS</p>
            </div>
        </body>
        </html>
        """
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Erreur envoi email invitation : {e}")
        return False


@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    org_id = current_user.organization_id
    user_project_ids = [pm.project_id for pm in current_user.projects_member]

    # Filtrer les projets par organisation
    projects = Project.query.filter(
        (Project.organization_id == org_id) &
        ((Project.user_id == current_user.id) | (Project.id.in_(user_project_ids)))
    ).all()

    total_tickets = 0
    critical_tickets = 0
    for project in projects:
        tickets = Ticket.query.filter_by(project_id=project.id, status='open').all()
        total_tickets += len(tickets)
        critical_tickets += len([t for t in tickets if t.severity == 'critical'])

    nis2_scores = []
    for project in projects:
        scan = project.latest_scan
        if scan and scan.results:
            data = json.loads(scan.results)
            if 'nis2_score' in data:
                nis2_scores.append(data['nis2_score'])
    avg_nis2 = round(sum(nis2_scores) / len(nis2_scores)) if nis2_scores else None

    return render_template(
        'dashboard.html',
        projects=projects,
        total_tickets=total_tickets,
        critical_tickets=critical_tickets,
        avg_nis2=avg_nis2,
        score_to_grade=score_to_grade,
        score_to_color=score_to_color
    )


@main_bp.route('/quick-scan', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 par heure")
def quick_scan():
    result = None
    url_scanned = None
    domain_scanned = None
    if request.method == 'POST':
        protocol = request.form.get('protocol', 'https://').strip()
        domain = request.form.get('domain', '').strip()
        if domain:
            url_scanned = protocol + domain
            domain_scanned = domain
            try:
                result = analyze_url(url_scanned)
            except Exception as e:
                flash(f'Erreur : {str(e)}', 'danger')
    return render_template(
        'quick_scan.html',
        result=result,
        url_scanned=url_scanned,
        domain_scanned=domain_scanned,
        score_to_grade=score_to_grade,
        score_to_color=score_to_color
    )


@main_bp.route('/tickets')
@login_required
def all_tickets():
    severity_filter = request.args.get('severity', '')
    status_filter = request.args.get('status', 'open')
    search = request.args.get('q', '').strip()

    org_id = current_user.organization_id

    # Récupérer les projets de l'organisation
    org_project_ids = [p.id for p in Project.query.filter_by(organization_id=org_id).all()]
    user_project_ids = [pm.project_id for pm in current_user.projects_member]

    accessible_project_ids = list(set(org_project_ids + user_project_ids))

    query = Ticket.query.filter(Ticket.project_id.in_(accessible_project_ids))

    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if search:
        query = query.filter(Ticket.title.ilike(f'%{search}%'))

    tickets = query.order_by(Ticket.created_at.desc()).all()

    projects_map = {p.id: p for p in Project.query.filter(Project.id.in_(accessible_project_ids)).all()}
    users = User.query.all()

    return render_template(
        'tickets.html',
        tickets=tickets,
        projects_map=projects_map,
        users=users,
        severity_filter=severity_filter,
        status_filter=status_filter,
        search=search
    )


@main_bp.route('/search')
@login_required
def search():
    q = request.args.get('q', '').strip()
    results = {'projects': [], 'tickets': []}

    org_id = current_user.organization_id
    org_project_ids = [p.id for p in Project.query.filter_by(organization_id=org_id).all()]
    user_project_ids = [pm.project_id for pm in current_user.projects_member]
    accessible_project_ids = list(set(org_project_ids + user_project_ids))

    if q:
        results['projects'] = Project.query.filter(
            Project.id.in_(accessible_project_ids),
            (Project.name.ilike(f'%{q}%') | Project.url.ilike(f'%{q}%'))
        ).all()

        results['tickets'] = Ticket.query.filter(
            Ticket.project_id.in_(accessible_project_ids),
            Ticket.title.ilike(f'%{q}%')
        ).all()

    projects_map = {p.id: p for p in Project.query.filter(Project.id.in_(accessible_project_ids)).all()}

    return render_template(
        'search.html',
        q=q,
        results=results,
        projects_map=projects_map,
        score_to_grade=score_to_grade,
        score_to_color=score_to_color
    )


@main_bp.route('/project/new', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 par heure")
def new_project():
    lenergy_presets = [
        {'name': 'API Check-Elec (Production)', 'url': 'https://api.lenergy-smart.fr', 'description': 'API principale des boîtiers Check-Elec'},
        {'name': 'Dashboard Client Check-Elec', 'url': 'https://app.lenergy-smart.fr', 'description': 'Interface client de suivi de consommation'},
        {'name': 'Site Lenergy Smart', 'url': 'https://lenergysmart.fr', 'description': 'Site vitrine public'},
        {'name': 'Portail Fournisseurs', 'url': 'https://fournisseurs.lenergy-smart.fr', 'description': 'Espace fournisseurs'},
        {'name': 'LenerWeb ESN', 'url': 'https://lenerweb.fr', 'description': 'Division IT & ESN'},
    ]
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        protocol = request.form.get('protocol', 'https://').strip()
        domain = request.form.get('domain', '').strip()
        url = protocol + domain
        description = request.form.get('description', '').strip()
        members_emails = request.form.get('members', '').strip()
        authorized_active_scan = request.form.get('authorized_active_scan') == 'on'

        if not name or not domain:
            flash('Le nom et le domaine sont obligatoires.', 'danger')
            return render_template('new_project.html', presets=lenergy_presets)

        project = Project(
            name=name,
            url=url,
            description=description,
            user_id=current_user.id,
            organization_id=current_user.organization_id,
            authorized_active_scan=authorized_active_scan
        )
        db.session.add(project)
        db.session.commit()

        # Ajouter les membres
        if members_emails:
            email_list = [e.strip().lower() for e in members_emails.split(',') if e.strip()]
            for email in email_list:
                user = User.query.filter_by(email=email).first()
                if user and user.id != current_user.id:
                    member = ProjectMember(project_id=project.id, user_id=user.id, role='member')
                    db.session.add(member)
                    send_project_invitation_email(user, project, current_user)
                    log = ActivityLog(
                        user_id=current_user.id,
                        action='add_member',
                        details=f'A ajouté {user.username} au projet {project.name}'
                    )
                    db.session.add(log)
            db.session.commit()

        flash(f'Projet "{name}" créé !', 'success')
        return redirect(url_for('main.project_detail', project_id=project.id))

    return render_template('new_project.html', presets=lenergy_presets)


@main_bp.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)

    # Vérifier que le projet appartient à l'organisation de l'utilisateur
    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))

    if project.user_id != current_user.id and not project.is_member(current_user.id):
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))

    scans = Scan.query.filter_by(project_id=project_id).order_by(Scan.created_at.desc()).all()
    tickets = Ticket.query.filter_by(project_id=project_id).order_by(Ticket.created_at.desc()).all()
    users = User.query.all()

    for scan in scans:
        scan.parsed_results = json.loads(scan.results) if scan.results else None

    chart_labels, chart_scores, chart_nis2 = [], [], []
    for scan in reversed(scans):
        if scan.status == 'done' and scan.score is not None:
            chart_labels.append(scan.created_at.strftime('%d/%m %H:%M'))
            chart_scores.append(scan.score)
            chart_nis2.append(json.loads(scan.results).get('nis2_score', 0) if scan.results else 0)

    return render_template(
        'project_detail.html',
        project=project,
        scans=scans,
        tickets=tickets,
        users=users,
        score_to_grade=score_to_grade,
        score_to_color=score_to_color,
        nis2_status_label=nis2_status_label,
        nis2_status_color=nis2_status_color,
        chart_labels=json.dumps(chart_labels),
        chart_scores=json.dumps(chart_scores),
        chart_nis2=json.dumps(chart_nis2)
    )


@main_bp.route('/project/<int:project_id>/scan', methods=['POST'])
@login_required
@limiter.limit("10 par heure")
def run_scan(project_id):
    project = Project.query.get_or_404(project_id)

    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))

    if project.user_id != current_user.id and not project.is_member(current_user.id):
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))

    scan = Scan(
        project_id=project_id,
        status='pending',
        launched_by=current_user.id,
        organization_id=current_user.organization_id
    )
    db.session.add(scan)
    db.session.commit()
    try:
        results = analyze_url(project.url, active_scan=project.authorized_active_scan)
        scan.score = results['score']
        scan.results = json.dumps(results)
        scan.status = 'done'
        Ticket.query.filter_by(project_id=project_id, status='open').delete()
        for ticket_data in results.get('tickets', []):
            ticket = Ticket(
                scan_id=scan.id,
                project_id=project_id,
                title=ticket_data['title'],
                description=ticket_data['description'],
                severity=ticket_data['severity'],
                status='open',
                organization_id=current_user.organization_id
            )
            db.session.add(ticket)

        log = ActivityLog(
            user_id=current_user.id,
            action='scan',
            details=f'Scan de {project.url} — score : {results["score"]}/100'
        )
        db.session.add(log)
        db.session.commit()

        if project.authorized_active_scan:
            flash(f'Scan terminé — Score : {results["score"]}/100 | NIS2 : {results["nis2_score"]}% (tests actifs OWASP inclus)', 'success')
        else:
            flash(f'Scan terminé — Score : {results["score"]}/100 | NIS2 : {results["nis2_score"]}% (tests passifs uniquement)', 'success')

    except Exception as e:
        scan.status = 'error'
        db.session.commit()
        flash(f'Erreur : {str(e)}', 'danger')
    return redirect(url_for('main.project_detail', project_id=project_id))


@main_bp.route('/project/<int:project_id>/nis2')
@login_required
def nis2_report(project_id):
    project = Project.query.get_or_404(project_id)

    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))

    if project.user_id != current_user.id and not project.is_member(current_user.id):
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))

    scan = project.latest_scan
    nis2_details, nis2_score = [], None
    if scan and scan.results:
        data = json.loads(scan.results)
        nis2_details = data.get('nis2_details', [])
        nis2_score = data.get('nis2_score')
    return render_template(
        'nis2_report.html',
        project=project,
        scan=scan,
        nis2_details=nis2_details,
        nis2_score=nis2_score,
        nis2_status_label=nis2_status_label,
        nis2_status_color=nis2_status_color
    )

@main_bp.route('/project/<int:project_id>/nis2/pdf')
@login_required
def nis2_pdf(project_id):
    flash(' La génération de PDF est désactivée. Utilisez le rapport HTML pour vos présentations.', 'info')
    return redirect(url_for('main.nis2_report', project_id=project_id))

@main_bp.route('/ticket/<int:ticket_id>/resolve', methods=['POST'])
@login_required
def resolve_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    project = Project.query.get(ticket.project_id)

    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce ticket.', 'danger')
        return redirect(url_for('main.all_tickets'))

    if project.user_id != current_user.id and not project.is_member(current_user.id):
        flash('Vous n\'avez pas accès à ce ticket.', 'danger')
        return redirect(url_for('main.all_tickets'))

    ticket.status = 'resolved'
    ticket.resolved_by = current_user.id
    ticket.resolved_at = datetime.utcnow()

    log = ActivityLog(
        user_id=current_user.id,
        action='resolve_ticket',
        details=f'Ticket résolu : "{ticket.title}"'
    )
    db.session.add(log)
    db.session.commit()
    flash('Ticket marqué comme résolu.', 'success')
    return redirect(request.referrer or url_for('main.all_tickets'))


@main_bp.route('/ticket/<int:ticket_id>/assign', methods=['POST'])
@login_required
def assign_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    project = Project.query.get(ticket.project_id)

    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce ticket.', 'danger')
        return redirect(url_for('main.all_tickets'))

    if project.user_id != current_user.id and not project.is_member(current_user.id):
        flash('Vous n\'avez pas accès à ce ticket.', 'danger')
        return redirect(url_for('main.all_tickets'))

    assigned_user_ids = request.form.getlist('user_ids')
    assigned_user_ids = [int(id) for id in assigned_user_ids if id]

    TicketAssignment.query.filter_by(ticket_id=ticket.id).delete()

    for user_id in assigned_user_ids:
        if project.is_member(user_id) or user_id == project.user_id:
            assignment = TicketAssignment(ticket_id=ticket.id, user_id=user_id)
            db.session.add(assignment)
        else:
            flash(f'L\'utilisateur {user_id} n\'est pas membre du projet.', 'warning')

    if assigned_user_ids:
        users = User.query.filter(User.id.in_(assigned_user_ids)).all()
        usernames = [u.username for u in users]
        log = ActivityLog(
            user_id=current_user.id,
            action='assign_ticket',
            details=f'Ticket "{ticket.title}" assigné à {", ".join(usernames)}'
        )
        db.session.add(log)
    else:
        log = ActivityLog(
            user_id=current_user.id,
            action='assign_ticket',
            details=f'Assignations supprimées pour le ticket "{ticket.title}"'
        )
        db.session.add(log)

    db.session.commit()
    flash('Assignations mises à jour.', 'success')
    return redirect(request.referrer or url_for('main.all_tickets'))


@main_bp.route('/project/<int:project_id>/add-members', methods=['POST'])
@login_required
def add_members(project_id):
    project = Project.query.get_or_404(project_id)

    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))

    if project.user_id != current_user.id and not project.is_manager(current_user.id):
        flash('Vous n\'avez pas les droits pour ajouter des membres.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))

    emails = request.form.get('emails', '').strip()
    if not emails:
        flash('Veuillez saisir au moins un email.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))

    email_list = [e.strip().lower() for e in emails.split(',') if e.strip()]
    added = []
    not_found = []
    already_member = []

    for email in email_list:
        user = User.query.filter_by(email=email).first()
        if not user:
            not_found.append(email)
        elif project.is_member(user.id) or user.id == project.user_id:
            already_member.append(email)
        else:
            member = ProjectMember(project_id=project.id, user_id=user.id, role='member')
            db.session.add(member)
            send_project_invitation_email(user, project, current_user)
            log = ActivityLog(
                user_id=current_user.id,
                action='add_member',
                details=f'A ajouté {user.username} au projet {project.name}'
            )
            db.session.add(log)
            added.append(email)

    db.session.commit()

    msg_parts = []
    if added:
        msg_parts.append(f'{len(added)} membre(s) ajouté(s)')
    if not_found:
        msg_parts.append(f'Email(s) introuvable(s) : {", ".join(not_found)}')
    if already_member:
        msg_parts.append(f'Déjà membres : {", ".join(already_member)}')

    flash(' — '.join(msg_parts), 'info' if added else 'warning')
    return redirect(url_for('main.project_detail', project_id=project.id))


@main_bp.route('/project/<int:project_id>/remove-member/<int:user_id>', methods=['POST'])
@login_required
def remove_member(project_id, user_id):
    project = Project.query.get_or_404(project_id)

    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))

    if user_id == project.user_id:
        flash('Vous ne pouvez pas retirer le créateur du projet.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))

    if project.user_id != current_user.id and not project.is_manager(current_user.id):
        flash('Vous n\'avez pas les droits pour retirer des membres.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))

    member = ProjectMember.query.filter_by(project_id=project_id, user_id=user_id).first()
    if member:
        log = ActivityLog(
            user_id=current_user.id,
            action='remove_member',
            details=f'A retiré {member.user.username} du projet {project.name}'
        )
        db.session.add(log)
        db.session.delete(member)
        db.session.commit()
        flash('Membre retiré du projet.', 'info')
    else:
        flash('Ce membre n\'existe pas dans ce projet.', 'warning')

    return redirect(url_for('main.project_detail', project_id=project.id))


@main_bp.route('/project/<int:project_id>/change-role', methods=['POST'])
@login_required
def change_member_role(project_id):
    project = Project.query.get_or_404(project_id)

    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))

    if project.user_id != current_user.id:
        flash('Seul le créateur peut changer les rôles.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))

    user_id = request.form.get('user_id', type=int)
    new_role = request.form.get('role', 'member')

    if user_id == project.user_id:
        flash('Le créateur a déjà le rôle manager.', 'warning')
        return redirect(url_for('main.project_detail', project_id=project.id))

    member = ProjectMember.query.filter_by(project_id=project_id, user_id=user_id).first()
    if member:
        old_role = member.role
        member.role = new_role
        log = ActivityLog(
            user_id=current_user.id,
            action='change_role',
            details=f'A changé le rôle de {member.user.username} de {old_role} à {new_role} dans le projet {project.name}'
        )
        db.session.add(log)
        db.session.commit()
        flash(f'Rôle mis à jour pour {member.user.username}.', 'success')
    else:
        flash('Membre non trouvé.', 'danger')

    return redirect(url_for('main.project_detail', project_id=project.id))


@main_bp.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)

    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))

    if project.user_id != current_user.id:
        flash('Seul le créateur peut supprimer ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))

    db.session.delete(project)
    db.session.commit()
    flash(f'Projet "{project.name}" supprimé.', 'info')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/project/<int:project_id>/schedule', methods=['GET', 'POST'])
@login_required
def schedule_scan(project_id):
    project = Project.query.get_or_404(project_id)
    
    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if project.user_id != current_user.id and not project.is_manager(current_user.id):
        flash('Vous n\'avez pas les droits pour planifier des scans.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))
    
    existing = ScheduledScan.query.filter_by(project_id=project.id, active=True).first()
    
    if request.method == 'POST':
        frequency = request.form.get('frequency', 'daily')
        
        # ✅ Log de planification
        log = ActivityLog(
            user_id=current_user.id,
            action='schedule_scan',
            details=f'Planification d\'un scan {frequency} pour le projet "{project.name}"'
        )
        db.session.add(log)
        
        if existing:
            existing.frequency = frequency
            existing.next_run = datetime.utcnow()
            flash('Planification mise à jour.', 'success')
        else:
            scheduled = ScheduledScan(
                project_id=project.id,
                created_by=current_user.id,
                frequency=frequency,
                active=True,
                next_run=datetime.utcnow()
            )
            db.session.add(scheduled)
            db.session.commit()
            flash('Scan planifié avec succès !', 'success')
        
        db.session.commit()
        return redirect(url_for('main.project_detail', project_id=project.id))
    
    return render_template(
        'schedule_scan.html',
        project=project,
        scheduled=existing
    )


@main_bp.route('/project/<int:project_id>/unschedule', methods=['POST'])
@login_required
def unschedule_scan(project_id):
    project = Project.query.get_or_404(project_id)
    
    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    scheduled = ScheduledScan.query.filter_by(project_id=project.id, active=True).first()
    if scheduled:
        scheduled.active = False
        db.session.commit()
        
        # ✅ Log de désactivation
        log = ActivityLog(
            user_id=current_user.id,
            action='unschedule_scan',
            details=f'Désactivation du scan planifié pour le projet "{project.name}"'
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Scan désactivé.', 'info')
    else:
        flash('Aucune planification trouvée.', 'warning')
    
    return redirect(url_for('main.project_detail', project_id=project.id))


# ============================================================
# VALIDATION DE PROPRIÉTÉ DE DOMAINE
# ============================================================

@main_bp.route('/.well-known/devshield-verify/<token>')
def verify_domain_well_known(token):
    """
    Vérification de propriété de domaine via .well-known/.
    Le propriétaire du domaine doit placer ce fichier à l'URL :
    https://domaine.com/.well-known/devshield-verify/<token>
    """
    verification = DomainVerification.query.filter_by(token=token, verified=False).first()
    
    if not verification:
        return "Token invalide ou déjà utilisé.", 404
    
    # Vérifier si le token a expiré
    if verification.expires_at and verification.expires_at < datetime.utcnow():
        return "Token expiré. Veuillez en générer un nouveau.", 410
    
    # Marquer comme vérifié
    verification.verified = True
    db.session.commit()
    
    return "Domaine vérifié avec succès !", 200


@main_bp.route('/project/<int:project_id>/verify-domain', methods=['POST'])
@login_required
def verify_domain(project_id):
    """
    Génère un token de vérification pour un projet.
    Le propriétaire doit ensuite placer le fichier à l'URL :
    https://domaine.com/.well-known/devshield-verify/<token>
    """
    from urllib.parse import urlparse
    import secrets
    from datetime import timedelta
    
    project = Project.query.get_or_404(project_id)
    
    if project.organization_id != current_user.organization_id:
        flash('Vous n\'avez pas accès à ce projet.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if project.user_id != current_user.id and not project.is_manager(current_user.id):
        flash('Vous n\'avez pas les droits pour vérifier ce domaine.', 'danger')
        return redirect(url_for('main.project_detail', project_id=project.id))
    
    # Extraire le domaine de l'URL
    parsed = urlparse(project.url)
    domain = parsed.netloc
    
    # Générer le token
    token = secrets.token_urlsafe(32)
    
    # Supprimer les anciens tokens non vérifiés
    DomainVerification.query.filter_by(
        domain=domain,
        verified=False
    ).delete()
    
    # Créer la vérification
    verification = DomainVerification(
        domain=domain,
        token=token,
        expires_at=datetime.utcnow() + timedelta(days=7),
        project_id=project.id
    )
    db.session.add(verification)
    db.session.commit()
    
    # URL de vérification
    verify_url = f"https://{domain}/.well-known/devshield-verify/{token}"
    
    flash(f'🔑 Token de vérification généré. Placez un fichier à l\'URL suivante : {verify_url}', 'info')
    flash(f'💡 Après avoir placé le fichier, le domaine sera automatiquement vérifié.', 'info')
    
    return redirect(url_for('main.project_detail', project_id=project.id))


# ============================================================
# SCAN PUBLIC GRATUIT (LEAD MAGNET)
# ============================================================

@main_bp.route('/public-scan', methods=['GET', 'POST'])
def public_scan():
    """
    Scan public gratuit (passif uniquement) avec capture d'email.
    Accessible sans authentification.
    """
    from app.models import Lead
    import json
    
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        email = request.form.get('email', '').strip()
        
        if not domain or not email:
            flash('Veuillez saisir un domaine et un email.', 'danger')
            return render_template('public_scan.html')
        
        # Scan passif uniquement (active_scan=False)
        url = 'https://' + domain if not domain.startswith('http') else domain
        result = analyze_url(url, active_scan=False)
        
        # Sauvegarder le lead
        lead = Lead(
            email=email,
            domain=domain,
            scan_result=json.dumps(result)
        )
        db.session.add(lead)
        db.session.commit()
        
        return render_template(
            'public_scan_result.html',
            result=result,
            domain=domain,
            score_to_grade=score_to_grade,
            score_to_color=score_to_color
        )
    
    return render_template('public_scan.html')