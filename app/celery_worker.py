from celery import Celery
from app import create_app
from app.extensions import db
import os

app = create_app()

def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['result_backend'],
        broker=app.config['broker_url']
    )
    celery.conf.update(app.config)
    
    # ✅ Configuration du scheduler Beat
    celery.conf.beat_schedule = {
        'check-scheduled-scans': {
            'task': 'app.tasks.check_scheduled_scans',
            'schedule': 60.0,  # Toutes les 60 secondes (1 minute)
        },
    }
    
    # ✅ Timezone pour éviter les problèmes de fuseau horaire
    celery.conf.timezone = 'UTC'
    
    # ✅ Découverte automatique des tâches
    celery.autodiscover_tasks(['app'])
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery

celery = make_celery(app)