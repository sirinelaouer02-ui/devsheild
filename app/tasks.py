from app.celery_worker import celery
from app.extensions import db
from app.models import ScheduledScan, Scan, Ticket, Project
from app.scanner import analyze_url
from flask import current_app
import json
from datetime import datetime, timedelta


@celery.task
def run_scheduled_scan(scan_id):
    """Execute un scan planifie."""
    from app import create_app
    app = create_app()
    with app.app_context():
        scheduled_scan = ScheduledScan.query.get(scan_id)
        if not scheduled_scan or not scheduled_scan.active:
            return {"status": "skipped", "reason": "not found or inactive"}
        
        project = scheduled_scan.project
        if not project:
            return {"status": "skipped", "reason": "project not found"}
        
        try:
            print(f"🚀 Scan du projet {project.name} ({project.url})")
            
            results = analyze_url(project.url, active_scan=project.authorized_active_scan)
            
            scan = Scan(
                project_id=project.id,
                score=results['score'],
                results=json.dumps(results),
                status='done',
                launched_by=scheduled_scan.created_by,
                organization_id=project.organization_id
            )
            db.session.add(scan)
            
            # Supprimer les anciens tickets ouverts
            Ticket.query.filter_by(project_id=project.id, status='open').delete()
            
            # Créer les nouveaux tickets
            for ticket_data in results.get('tickets', []):
                ticket = Ticket(
                    scan_id=scan.id,
                    project_id=project.id,
                    title=ticket_data['title'],
                    description=ticket_data['description'],
                    severity=ticket_data['severity'],
                    status='open',
                    organization_id=project.organization_id
                )
                db.session.add(ticket)
            
            # Mettre à jour les dates du scan planifié
            scheduled_scan.last_run = datetime.utcnow()
            
            if scheduled_scan.frequency == 'hourly':
                scheduled_scan.next_run = datetime.utcnow() + timedelta(hours=1)
            elif scheduled_scan.frequency == 'daily':
                scheduled_scan.next_run = datetime.utcnow() + timedelta(days=1)
            elif scheduled_scan.frequency == 'weekly':
                scheduled_scan.next_run = datetime.utcnow() + timedelta(days=7)
            elif scheduled_scan.frequency == 'monthly':
                scheduled_scan.next_run = datetime.utcnow() + timedelta(days=30)
            else:
                scheduled_scan.next_run = datetime.utcnow() + timedelta(days=1)
            
            db.session.commit()
            
            print(f"✅ Scan terminé pour {project.name} - Score: {results['score']}/100")
            
            return {
                "status": "success",
                "scan_id": scan.id,
                "score": results['score'],
                "tickets": len(results.get('tickets', []))
            }
            
        except Exception as e:
            print(f"❌ Erreur lors du scan de {project.name}: {str(e)}")
            scheduled_scan.last_run = datetime.utcnow()
            scheduled_scan.next_run = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            return {"status": "error", "error": str(e)}


@celery.task
def check_scheduled_scans():
    """Verifie les scans planifies et les execute si necessaire."""
    from app import create_app
    import sys
    
    app = create_app()
    with app.app_context():
        now = datetime.utcnow()
        
        # ✅ Log pour debugging
        print(f"🔍 Recherche de scans planifiés... (now={now})")
        
        # ✅ Compter tous les scans planifiés (même inactifs) pour debug
        total_scans = ScheduledScan.query.count()
        print(f"📊 Total des scans planifiés en base: {total_scans}")
        
        # ✅ Compter les scans actifs
        active_scans = ScheduledScan.query.filter_by(active=True).count()
        print(f"📊 Scans actifs: {active_scans}")
        
        # ✅ Récupérer les scans à exécuter
        scheduled_scans = ScheduledScan.query.filter(
            ScheduledScan.active == True,
            ScheduledScan.next_run <= now
        ).all()
        
        print(f"🔍 Scans à exécuter: {len(scheduled_scans)} trouvé(s)")
        
        # ✅ Afficher chaque scan pour debug
        for s in scheduled_scans:
            print(f"   - Scan ID: {s.id}, Projet: {s.project_id}, next_run: {s.next_run}")
        
        results = []
        for scheduled_scan in scheduled_scans:
            print(f"📅 Exécution du scan planifié pour le projet {scheduled_scan.project_id}")
            result = run_scheduled_scan.delay(scheduled_scan.id)
            results.append({
                "scheduled_scan_id": scheduled_scan.id,
                "task_id": result.id
            })
        
        return results


@celery.task
def send_scan_report_email(scan_id, recipient_email):
    """Envoie un email avec les resultats du scan."""
    from app import create_app
    from flask_mail import Message
    from app import mail
    
    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return {"status": "error", "reason": "scan not found"}
        
        results = json.loads(scan.results) if scan.results else {}
        
        msg = Message(
            subject=f"[DevShield] Rapport de scan - {scan.project.name}",
            recipients=[recipient_email],
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2>Rapport de scan DevShield</h2>
            <p>Projet : <strong>{scan.project.name}</strong></p>
            <p>URL : <strong>{scan.project.url}</strong></p>
            <p>Score : <strong>{scan.score}/100</strong></p>
            <p>NIS2 : <strong>{results.get('nis2_score', 0)}%</strong></p>
            <p>Tickets trouves : <strong>{len(results.get('tickets', []))}</strong></p>
            <p><a href="http://localhost:5000/project/{scan.project.id}">Voir le detail</a></p>
        </body>
        </html>
        """
        mail.send(msg)
        return {"status": "success"}