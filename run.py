from app import create_app
from app.models import db, User

app = create_app()

def create_default_admin():
    with app.app_context():
        # Vérifie si Angelo existe déjà
        existing = User.query.filter_by(username='angelo').first()
        if not existing:
            admin = User(
                username='angelo',
                email='angelo@lenergysmart.fr',
                role='admin',
                is_active=True
            )
            admin.set_password('DevShield@2026')
            db.session.add(admin)
            db.session.commit()
            print('Compte admin "angelo" créé avec succès.')
        else:
            print('Compte admin "angelo" déjà existant.')

# Créer les tables si elles n'existent pas
with app.app_context():
    db.create_all()
    print('Base de données initialisée (PostgreSQL).')

create_default_admin()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)