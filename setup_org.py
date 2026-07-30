from app import create_app, db
from app.models import Organization, User

app = create_app()
with app.app_context():
    # 1. Vérifier si l'utilisateur admin existe
    admin = User.query.filter_by(username='angelo').first()
    if not admin:
        admin = User(
            username='angelo',
            email='angelo@lenergysmart.fr',
            role='admin',
            is_active=True
        )
        admin.set_password('DevShield@2026')
        db.session.add(admin)
        db.session.commit()
        print(f"Utilisateur admin cree : {admin.username} (ID: {admin.id})")
    else:
        print(f"Utilisateur admin existe deja : {admin.username} (ID: {admin.id})")

    # 2. Créer l'organisation Lenergy
    org = Organization.query.filter_by(slug="lenergy").first()
    if not org:
        org = Organization(
            name="Lenergy Smart",
            slug="lenergy",
            description="Organisation principale Lenergy Smart",
            created_by=admin.id
        )
        db.session.add(org)
        db.session.commit()
        print(f"Organisation creee : {org.name} (ID: {org.id})")
    else:
        print(f"Organisation existe deja : {org.name} (ID: {org.id})")

    # 3. Rattacher tous les utilisateurs à cette organisation
    org = Organization.query.filter_by(slug="lenergy").first()
    if org:
        users = User.query.all()
        for user in users:
            if user.organization_id is None:
                user.organization_id = org.id
        db.session.commit()
        updated = sum(1 for u in User.query.all() if u.organization_id == org.id)
        print(f"{updated} utilisateur(s) rattache(s) a {org.name}")
    else:
        print("Organisation non trouvee")