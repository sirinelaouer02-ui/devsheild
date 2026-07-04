import os
from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response
from flask_login import login_required, current_user
import json
from datetime import datetime
from .models import db, Project, Scan, Ticket
from .scanner import (analyze_url, score_to_grade, score_to_color,
                       nis2_status_label, nis2_status_color)

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


@main_bp.route('/project/new', methods=['GET', 'POST'])
@login_required
def new_project():
    lenergy_presets = [
        {'name': 'API Check-Elec (Production)', 'url': 'https://api.lenergysmart.fr', 'description': 'API principale des boîtiers Check-Elec'},
        {'name': 'Dashboard Client Check-Elec', 'url': 'https://app.lenergy-smart.fr', 'description': 'Interface client de suivi de consommation'},
        {'name': 'Site Lenergy Smart', 'url': 'https://lenergysmart.fr', 'description': 'Site vitrine public'},
        {'name': 'Portail Fournisseurs', 'url': 'https://fournisseurs.lenergy-smart.fr', 'description': 'Espace fournisseurs'},
        {'name': 'LenerWeb ESN', 'url': 'https://lenerweb.fr', 'description': 'Division IT & ESN'},
    ]

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        url = request.form.get('url', '').strip()
        description = request.form.get('description', '').strip()

        if not name or not url:
            flash('Le nom et l\'URL sont obligatoires.', 'danger')
            return render_template('new_project.html', presets=lenergy_presets)

        project = Project(name=name, url=url, description=description, user_id=current_user.id)
        db.session.add(project)
        db.session.commit()

        flash(f'Projet "{name}" créé !', 'success')
        return redirect(url_for('main.project_detail', project_id=project.id))

    return render_template('new_project.html', presets=lenergy_presets)


@main_bp.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    scans = Scan.query.filter_by(project_id=project_id).order_by(Scan.created_at.desc()).all()
    tickets = Ticket.query.filter_by(project_id=project_id).order_by(Ticket.created_at.desc()).all()

    for scan in scans:
        if scan.results:
            scan.parsed_results = json.loads(scan.results)
        else:
            scan.parsed_results = None

    chart_labels = []
    chart_scores = []
    chart_nis2 = []
    scans_chrono = list(reversed(scans))
    for scan in scans_chrono:
        if scan.status == 'done' and scan.score is not None:
            chart_labels.append(scan.created_at.strftime('%d/%m %H:%M'))
            chart_scores.append(scan.score)
            if scan.results:
                data = json.loads(scan.results)
                chart_nis2.append(data.get('nis2_score', 0))
            else:
                chart_nis2.append(0)

    return render_template(
        'project_detail.html',
        project=project,
        scans=scans,
        tickets=tickets,
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
def run_scan(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()

    scan = Scan(
        project_id=project_id,
        status='pending',
        triggered_by=f'manuel:{current_user.username}'
    )
    db.session.add(scan)
    db.session.commit()

    try:
        results = analyze_url(project.url)
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
                status='open'
            )
            db.session.add(ticket)
        db.session.commit()

        flash(
            f'Scan terminé — Score : {results["score"]}/100 | Conformité NIS2 : {results["nis2_score"]}%',
            'success'
        )
    except Exception as e:
        scan.status = 'error'
        db.session.commit()
        flash(f'Erreur pendant le scan : {str(e)}', 'danger')

    return redirect(url_for('main.project_detail', project_id=project_id))


@main_bp.route('/api/webhook/scan/<int:project_id>', methods=['POST'])
def webhook_scan(project_id):
    secret = request.headers.get('X-Webhook-Secret')
    expected = os.environ.get('WEBHOOK_SECRET')

    if not expected or secret != expected:
        return {'error': 'unauthorized'}, 401

    project = Project.query.get_or_404(project_id)
    commit_sha = request.headers.get('X-Commit-Sha', 'inconnu')[:7]

    scan = Scan(
        project_id=project_id,
        status='pending',
        triggered_by=f'auto:GitHub Actions:{commit_sha}'
    )
    db.session.add(scan)
    db.session.commit()

    try:
        results = analyze_url(project.url)
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
                status='open'
            )
            db.session.add(ticket)
        db.session.commit()

        return {
            'status': 'success',
            'score': results['score'],
            'nis2_score': results['nis2_score']
        }, 200

    except Exception as e:
        scan.status = 'error'
        db.session.commit()
        return {'error': str(e)}, 500


@main_bp.route('/project/<int:project_id>/nis2')
@login_required
def nis2_report(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    scan = project.latest_scan
    nis2_details = []
    nis2_score = None
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
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    scan = project.latest_scan
    nis2_details = []
    nis2_score = None
    scan_results = None
    if scan and scan.results:
        data = json.loads(scan.results)
        nis2_details = data.get('nis2_details', [])
        nis2_score = data.get('nis2_score')
        scan_results = data

    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm,
        leftMargin=20 * mm, rightMargin=20 * mm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleCustom', parent=styles['Title'],
                                  textColor=HexColor('#6366f1'), fontSize=20, spaceAfter=2)
    subtitle_style = ParagraphStyle('SubtitleCustom', parent=styles['Normal'],
                                     textColor=HexColor('#6b7280'), fontSize=10, spaceAfter=14)
    section_style = ParagraphStyle('SectionCustom', parent=styles['Heading2'],
                                    textColor=HexColor('#1a1d2e'), fontSize=13, spaceBefore=16, spaceAfter=8)
    normal_style = ParagraphStyle('NormalCustom', parent=styles['Normal'], fontSize=10, leading=14)
    small_muted = ParagraphStyle('SmallMuted', parent=styles['Normal'],
                                  fontSize=9, textColor=HexColor('#6b7280'))

    elements = []
    elements.append(Paragraph('DevShield — Rapport NIS2', title_style))
    elements.append(Paragraph(f'{project.name} — {project.url}', subtitle_style))
    elements.append(HRFlowable(width='100%', color=HexColor('#e5e7eb'), thickness=1))
    elements.append(Spacer(1, 10))

    generated_at = datetime.utcnow().strftime('%d/%m/%Y à %H:%M')
    elements.append(Paragraph(f'Généré le {generated_at} — Confidentiel, usage interne Lenergy Smart', small_muted))
    elements.append(Spacer(1, 14))

    score_val = scan.score if scan and scan.score is not None else 'N/A'
    nis2_val = f'{nis2_score}%' if nis2_score is not None else 'N/A'
    summary_data = [
        ['Application', 'Score sécurité', 'Conformité NIS2', 'Date du scan'],
        [
            project.name,
            str(score_val),
            nis2_val,
            scan.created_at.strftime('%d/%m/%Y') if scan else 'Aucun scan'
        ]
    ]
    summary_table = Table(summary_data, colWidths=[130, 90, 90, 90])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f3f4f6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#6b7280')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e5e7eb')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(summary_table)

    if nis2_details:
        elements.append(Paragraph('Analyse par critère NIS2', section_style))
        status_labels = {'conforme': 'Conforme', 'partiel': 'Partiel', 'non_conforme': 'Non conforme'}
        status_colors = {'conforme': '#16a34a', 'partiel': '#ea580c', 'non_conforme': '#dc2626'}
        for c in nis2_details:
            color = status_colors.get(c['status'], '#6b7280')
            label = status_labels.get(c['status'], c['status'])
            elements.append(Paragraph(
                f'<font color="{color}"><b>{label}</b></font> — <b>{c["label"]}</b>',
                normal_style
            ))
            elements.append(Paragraph(c['description'], small_muted))
            elements.append(Spacer(1, 8))

    if scan_results and scan_results.get('checks'):
        elements.append(Paragraph('Détail des vérifications techniques', section_style))
        check_rows = [['Vérification', 'Statut', 'Détail']]
        for check in scan_results['checks']:
            status_txt = {'pass': 'OK', 'fail': 'Échec', 'warn': 'Attention'}.get(check['status'], check['status'])
            check_rows.append([
                Paragraph(check['name'], small_muted),
                status_txt,
                Paragraph(check['detail'][:120], small_muted)
            ])
        check_table = Table(check_rows, colWidths=[150, 55, 195])
        check_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f3f4f6')),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e5e7eb')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(check_table)

    if nis2_details:
        non_conformes = [d for d in nis2_details if d['status'] == 'non_conforme']
        partiels = [d for d in nis2_details if d['status'] == 'partiel']
        if non_conformes or partiels:
            elements.append(Paragraph('Recommandations prioritaires', section_style))
            for item in non_conformes:
                elements.append(Paragraph('<font color="#dc2626"><b>PRIORITÉ HAUTE</b></font>', small_muted))
                elements.append(Paragraph(f'<b>{item["label"]}</b>', normal_style))
                elements.append(Paragraph(item['description'], small_muted))
                elements.append(Spacer(1, 8))
            for item in partiels:
                elements.append(Paragraph('<font color="#ea580c"><b>PRIORITÉ MOYENNE</b></font>', small_muted))
                elements.append(Paragraph(f'<b>{item["label"]}</b>', normal_style))
                elements.append(Paragraph(item['description'], small_muted))
                elements.append(Spacer(1, 8))

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width='100%', color=HexColor('#e5e7eb'), thickness=1))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph('DevShield — Plateforme DevSecOps interne Lenergy Smart', small_muted))

    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=rapport-nis2-{project.id}.pdf'
    return response


@main_bp.route('/ticket/<int:ticket_id>/resolve', methods=['POST'])
@login_required
def resolve_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
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