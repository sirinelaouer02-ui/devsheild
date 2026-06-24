from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
import json

from .models import db, Project, Scan, Ticket
from .scanner import analyze_url, score_to_grade, score_to_color

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    
    # Calcule les stats globales
    total_tickets = 0
    critical_tickets = 0
    for project in projects:
        tickets = Ticket.query.filter_by(project_id=project.id, status='open').all()
        total_tickets += len(tickets)
        critical_tickets += len([t for t in tickets if t.severity == 'critical'])
    
    return render_template(
        'dashboard.html',
        projects=projects,
        total_tickets=total_tickets,
        critical_tickets=critical_tickets,
        score_to_grade=score_to_grade,
        score_to_color=score_to_color
    )


@main_bp.route('/project/new', methods=['GET', 'POST'])
@login_required
def new_project():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        url = request.form.get('url', '').strip()
        description = request.form.get('description', '').strip()
        
        if not name or not url:
            flash('Le nom et l\'URL sont obligatoires.', 'danger')
            return render_template('new_project.html')
        
        project = Project(
            name=name,
            url=url,
            description=description,
            user_id=current_user.id
        )
        db.session.add(project)
        db.session.commit()
        
        flash(f'Projet "{name}" créé !', 'success')
        return redirect(url_for('main.project_detail', project_id=project.id))
    
    return render_template('new_project.html')


@main_bp.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    scans = Scan.query.filter_by(project_id=project_id).order_by(Scan.created_at.desc()).all()
    tickets = Ticket.query.filter_by(project_id=project_id).order_by(Ticket.created_at.desc()).all()
    
    # Parse les résultats JSON de chaque scan
    for scan in scans:
        if scan.results:
            scan.parsed_results = json.loads(scan.results)
        else:
            scan.parsed_results = None
    
    return render_template(
        'project_detail.html',
        project=project,
        scans=scans,
        tickets=tickets,
        score_to_grade=score_to_grade,
        score_to_color=score_to_color
    )


@main_bp.route('/project/<int:project_id>/scan', methods=['POST'])
@login_required
def run_scan(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    
    # Crée un scan en base
    scan = Scan(project_id=project_id, status='pending')
    db.session.add(scan)
    db.session.commit()
    
    # Lance l'analyse
    try:
        results = analyze_url(project.url)
        scan.score = results['score']
        scan.results = json.dumps(results)
        scan.status = 'done'
        
        # Crée les tickets pour les failles trouvées
        for ticket_data in results.get('tickets', []):
            ticket = Ticket(
                scan_id=scan.id,
                project_id=project_id,
                title=ticket_data['title'],
                description=ticket_data['description'],
                severity=ticket_data['severity'],
                status='open'
            )
            db.session.add(ticket)
        
        db.session.commit()
        flash(f'Scan terminé ! Score de sécurité : {results["score"]}/100', 'success')
    
    except Exception as e:
        scan.status = 'error'
        db.session.commit()
        flash(f'Erreur pendant le scan : {str(e)}', 'danger')
    
    return redirect(url_for('main.project_detail', project_id=project_id))


@main_bp.route('/ticket/<int:ticket_id>/resolve', methods=['POST'])
@login_required
def resolve_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # Vérifie que le ticket appartient à l'utilisateur connecté
    project = Project.query.filter_by(id=ticket.project_id, user_id=current_user.id).first_or_404()
    
    ticket.status = 'resolved'
    db.session.commit()
    flash('Ticket marqué comme résolu.', 'success')
    return redirect(url_for('main.project_detail', project_id=project.id))


@main_bp.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    db.session.delete(project)
    db.session.commit()
    flash(f'Projet "{project.name}" supprimé.', 'info')
    return redirect(url_for('main.dashboard'))