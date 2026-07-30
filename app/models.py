from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import current_app
import secrets
import pyotp
from .extensions import db


class Organization(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    slug = db.Column(db.String(80), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    users = db.relationship('User', back_populates='organization', lazy=True, foreign_keys='User.organization_id')
    projects = db.relationship('Project', back_populates='organization', lazy=True)
    creator = db.relationship('User', foreign_keys=[created_by])

    def __repr__(self):
        return f'<Organization {self.name}>'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), default='developer')
    is_active = db.Column(db.Boolean, default=True)
    must_change_password = db.Column(db.Boolean, default=True)
    setup_token = db.Column(db.String(100), nullable=True, unique=True)
    setup_token_expires = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 2FA
    otp_secret = db.Column(db.String(32), nullable=True)
    otp_enabled = db.Column(db.Boolean, default=False)

    # Organisation (multi-tenant)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)

    # Relations
    organization = db.relationship('Organization', back_populates='users', foreign_keys=[organization_id])
    projects = db.relationship('Project', backref='owner', lazy=True,
                               foreign_keys='Project.user_id')
    projects_member = db.relationship('ProjectMember', back_populates='user')
    ticket_assignments = db.relationship('TicketAssignment', back_populates='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def generate_setup_token(self):
        from datetime import timedelta
        self.setup_token = secrets.token_urlsafe(32)
        self.setup_token_expires = datetime.utcnow() + timedelta(hours=24)
        return self.setup_token

    def generate_reset_token(self, expires_sec=3600):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token = s.dumps(self.id, salt='reset-password')
        print(f"🔐 Token généré pour l'utilisateur {self.id} ({self.email}) : {token[:50]}...")
        return token

    @staticmethod
    def verify_reset_token(token, expires_sec=3600):
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            print(f"🔓 Vérification du token : {token[:50]}...")
            user_id = s.loads(token, salt='reset-password', max_age=expires_sec)
            print(f"✅ Token valide ! User ID trouvé : {user_id}")
            return User.query.get(user_id)
        except SignatureExpired as e:
            print(f"❌ Token EXPIRÉ : {e}")
            return None
        except BadSignature as e:
            print(f"❌ Token INVALIDE (signature incorrecte) : {e}")
            return None

    # 2FA methods
    def enable_otp(self):
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
        self.otp_enabled = True
        db.session.commit()

    def disable_otp(self):
        self.otp_secret = None
        self.otp_enabled = False
        db.session.commit()

    def get_otp_uri(self):
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
            db.session.commit()
        issuer = current_app.config.get('OTP_ISSUER', 'DevShield')
        return pyotp.totp.TOTP(self.otp_secret).provisioning_uri(
            name=self.email,
            issuer_name=issuer
        )

    def verify_otp(self, token):
        if not self.otp_secret or not self.otp_enabled:
            return False
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token, valid_window=1)

    @property
    def accessible_projects(self):
        return [pm.project for pm in self.projects_member]

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_manager(self):
        return self.role in ('admin', 'manager')

    @property
    def role_label(self):
        labels = {
            'admin': 'Administrateur',
            'manager': 'Manager',
            'developer': 'Développeur'
        }
        return labels.get(self.role, self.role)

    @property
    def role_color(self):
        colors = {
            'admin': 'red',
            'manager': 'orange',
            'developer': 'primary'
        }
        return colors.get(self.role, 'primary')


class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)
    authorized_active_scan = db.Column(db.Boolean, default=False)

    organization = db.relationship('Organization', back_populates='projects')
    scans = db.relationship('Scan', backref='project', lazy=True,
                            cascade='all, delete-orphan')
    members = db.relationship('ProjectMember', back_populates='project',
                              cascade='all, delete-orphan')

    @property
    def latest_scan(self):
        return Scan.query.filter_by(
            project_id=self.id
        ).order_by(Scan.created_at.desc()).first()

    @property
    def security_score(self):
        scan = self.latest_scan
        return scan.score if scan else None

    @property
    def member_users(self):
        return [pm.user for pm in self.members]

    @property
    def member_ids(self):
        return [pm.user_id for pm in self.members]

    @property
    def manager_ids(self):
        return [pm.user_id for pm in self.members if pm.role == 'manager']

    def is_member(self, user_id):
        return user_id in self.member_ids or user_id == self.user_id

    def is_manager(self, user_id):
        return user_id in self.manager_ids or user_id == self.user_id


class ProjectMember(db.Model):
    __tablename__ = 'project_members'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    project = db.relationship('Project', back_populates='members')
    user = db.relationship('User', back_populates='projects_member')


class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    score = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default='pending')
    results = db.Column(db.Text, nullable=True)
    launched_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)

    launcher = db.relationship('User', foreign_keys=[launched_by])


class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='open')
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True)

    resolver = db.relationship('User', foreign_keys=[resolved_by])
    assignments = db.relationship('TicketAssignment', back_populates='ticket', cascade='all, delete-orphan')

    @property
    def assigned_users(self):
        return [ta.user for ta in self.assignments]

    @property
    def assigned_to_list(self):
        return [ta.user_id for ta in self.assignments]


class TicketAssignment(db.Model):
    __tablename__ = 'ticket_assignments'
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

    ticket = db.relationship('Ticket', back_populates='assignments')
    user = db.relationship('User', back_populates='ticket_assignments')


class ComplianceChecklist(db.Model):
    __tablename__ = 'compliance_checklists'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    direction_formee = db.Column(db.Boolean, default=False)
    politique_securite_ecrite = db.Column(db.Boolean, default=False)
    analyse_risques_realisee = db.Column(db.Boolean, default=False)
    plan_continuite_redige = db.Column(db.Boolean, default=False)
    plan_reprise_teste = db.Column(db.Boolean, default=False)
    procedure_notification_incident = db.Column(db.Boolean, default=False)
    cellule_crise_designee = db.Column(db.Boolean, default=False)
    fournisseurs_evalues = db.Column(db.Boolean, default=False)
    clauses_securite_contrats = db.Column(db.Boolean, default=False)
    formation_personnel_reguliere = db.Column(db.Boolean, default=False)
    registre_traitements_rgpd = db.Column(db.Boolean, default=False)

    project = db.relationship('Project', backref=db.backref(
        'compliance_checklist', uselist=False, cascade='all, delete-orphan'))
    updater = db.relationship('User', foreign_keys=[updated_by])

    ITEMS = [
        ('direction_formee', 'La direction a suivi une formation cybersecurite', 'Art. 20'),
        ('politique_securite_ecrite', 'Une politique de securite des systemes d\'information (PSSI) est redigee', 'Art. 21.2.a'),
        ('analyse_risques_realisee', 'Une analyse de risques cyber a ete realisee', 'Art. 21.2.a'),
        ('plan_continuite_redige', 'Un plan de continuite d\'activite (PCA) existe et est a jour', 'Art. 21.2.c'),
        ('plan_reprise_teste', 'Un plan de reprise d\'activite (PRA) a ete teste', 'Art. 21.2.c'),
        ('procedure_notification_incident', 'Une procedure de notification d\'incident (24h/72h) est documentee', 'Art. 21.2.b'),
        ('cellule_crise_designee', 'Une cellule de crise avec referents nommes est designee', 'Art. 21.2.b'),
        ('fournisseurs_evalues', 'Les fournisseurs/prestataires critiques sont evalues sur leur securite', 'Art. 21.2.d'),
        ('clauses_securite_contrats', 'Les contrats fournisseurs incluent des clauses de securite', 'Art. 21.2.d'),
        ('formation_personnel_reguliere', 'Le personnel recoit une formation cybersecurite reguliere', 'Art. 21.2.g'),
        ('registre_traitements_rgpd', 'Un registre des traitements RGPD est tenu a jour', 'RGPD Art. 30'),
    ]

    @property
    def org_score(self):
        total = len(self.ITEMS)
        checked = sum(1 for field, _, _ in self.ITEMS if getattr(self, field))
        return round((checked / total) * 100) if total else 0

    @property
    def checked_count(self):
        return sum(1 for field, _, _ in self.ITEMS if getattr(self, field))


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id])


class ScheduledScan(db.Model):
    __tablename__ = 'scheduled_scans'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    frequency = db.Column(db.String(20), default='daily')
    active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime, nullable=True)
    next_run = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    project = db.relationship('Project', backref='scheduled_scans')
    creator = db.relationship('User', foreign_keys=[created_by])
    
    def __repr__(self): 
        return f'<ScheduledScan {self.project.name} - {self.frequency}>'


# ✅ Modèle pour la validation de propriété de domaine
class DomainVerification(db.Model):
    __tablename__ = 'domain_verifications'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(64), nullable=False, unique=True)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=True)
    
    project = db.relationship('Project', backref='domain_verifications')
    
    def __repr__(self):
        return f'<DomainVerification {self.domain} - {self.verified}>'


# ✅ Modèle pour les leads (scan public gratuit)
class Lead(db.Model):
    __tablename__ = 'leads'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    scan_result = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Lead {self.email} - {self.domain}>'