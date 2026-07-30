"""
Utilitaires pour la gestion multi-tenant (organisations)
"""
from flask_login import current_user
from .models import db, Organization, User, Project, Scan, Ticket


def get_current_user_organization():
    """Retourne l'organisation de l'utilisateur connecté."""
    if not current_user.is_authenticated:
        return None
    return current_user.organization


def filter_by_organization(query, model, org_id=None):
    """
    Filtre une requête SQLAlchemy par organisation.
    Si org_id est None, utilise l'organisation de l'utilisateur connecté.
    """
    if org_id is None and current_user.is_authenticated:
        org_id = current_user.organization_id

    if org_id is not None and hasattr(model, 'organization_id'):
        return query.filter(model.organization_id == org_id)
    return query


def get_organization_projects(org_id=None):
    """Retourne tous les projets d'une organisation."""
    if org_id is None and current_user.is_authenticated:
        org_id = current_user.organization_id

    if org_id is None:
        return []

    return Project.query.filter_by(organization_id=org_id).all()


def get_organization_users(org_id=None):
    """Retourne tous les utilisateurs d'une organisation."""
    if org_id is None and current_user.is_authenticated:
        org_id = current_user.organization_id

    if org_id is None:
        return []

    return User.query.filter_by(organization_id=org_id).all()


def is_same_organization(user1, user2):
    """Vérifie si deux utilisateurs appartiennent à la même organisation."""
    if not user1 or not user2:
        return False
    return user1.organization_id == user2.organization_id


def create_organization(name, slug, description=None, created_by=None):
    """Crée une nouvelle organisation."""
    org = Organization(
        name=name,
        slug=slug,
        description=description,
        created_by=created_by
    )
    db.session.add(org)
    db.session.commit()
    return org


def get_user_organization(user):
    """Retourne l'organisation d'un utilisateur."""
    if not user:
        return None
    return user.organization