"""SQLAlchemy ORM models."""
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Float, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(30), nullable=False)  # admin, investigator, analyst, viewer
    full_name = Column(String(150))
    department = Column(String(100))
    badge_number = Column(String(50))
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)

    cases_created = relationship('Case', back_populates='creator', foreign_keys='Case.created_by')
    assignments = relationship('CaseAssignment', back_populates='user', foreign_keys='CaseAssignment.user_id')
    evidence_uploaded = relationship('Evidence', back_populates='uploader', foreign_keys='Evidence.uploaded_by')
    audit_logs = relationship('AuditLog', back_populates='user', foreign_keys='AuditLog.user_id')


class Case(Base):
    __tablename__ = 'cases'
    id = Column(Integer, primary_key=True)
    case_number = Column(String(50), unique=True, nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    status = Column(String(30), default='open')  # open, active, closed, archived
    priority = Column(String(20), default='medium')  # low, medium, high, critical
    location = Column(String(200))
    incident_date = Column(DateTime)
    created_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    creator = relationship('User', back_populates='cases_created', foreign_keys=[created_by])
    assignments = relationship('CaseAssignment', back_populates='case', cascade='all, delete-orphan')
    evidence = relationship('Evidence', back_populates='case', cascade='all, delete-orphan')


class CaseAssignment(Base):
    __tablename__ = 'case_assignments'
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    role_in_case = Column(String(50))
    assigned_by = Column(Integer, ForeignKey('users.id'))
    assigned_at = Column(DateTime, default=datetime.utcnow)

    case = relationship('Case', back_populates='assignments')
    user = relationship('User', back_populates='assignments', foreign_keys=[user_id])


class Evidence(Base):
    __tablename__ = 'evidence'
    id = Column(Integer, primary_key=True)
    evidence_number = Column(String(50), unique=True, nullable=False)
    case_id = Column(Integer, ForeignKey('cases.id'), nullable=False)
    filename = Column(String(300), nullable=False)
    original_filename = Column(String(300), nullable=False)
    file_size = Column(Integer)
    file_size_human = Column(String(30))
    mime_type = Column(String(100))
    sha256_hash = Column(String(64), nullable=False, unique=True)
    md5_hash = Column(String(32))
    evidence_type = Column(String(50))  # pcap, image, log, document, video, malware, other
    description = Column(Text)
    location_found = Column(String(200))
    tags = Column(Text)
    status = Column(String(30), default='pending')  # pending, verified, tampered, transferred
    blockchain_tx = Column(String(100))
    blockchain_block = Column(Integer)
    chain_of_custody_count = Column(Integer, default=0)
    metadata_json = Column(Text)
    uploaded_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    case = relationship('Case', back_populates='evidence')
    uploader = relationship('User', back_populates='evidence_uploaded', foreign_keys=[uploaded_by])
    custody_logs = relationship('CustodyLog', back_populates='evidence', cascade='all, delete-orphan')
    analyst_notes = relationship('AnalystNote', back_populates='evidence', cascade='all, delete-orphan')


class CustodyLog(Base):
    __tablename__ = 'custody_logs'
    id = Column(Integer, primary_key=True)
    evidence_id = Column(Integer, ForeignKey('evidence.id'), nullable=False)
    action = Column(String(50))  # uploaded, verified, transferred, downloaded, analyzed
    from_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    to_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    ip_address = Column(String(45))
    blockchain_tx = Column(String(100))
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

    evidence = relationship('Evidence', back_populates='custody_logs')


class AnalystNote(Base):
    __tablename__ = 'analyst_notes'
    id = Column(Integer, primary_key=True)
    evidence_id = Column(Integer, ForeignKey('evidence.id'), nullable=False)
    analyst_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    content = Column(Text, nullable=False)
    classification = Column(String(50), default='internal')  # internal, confidential, top_secret
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    evidence = relationship('Evidence', back_populates='analyst_notes')


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(50))
    ip_address = Column(String(45))
    user_agent = Column(String(300))
    details = Column(Text)
    severity = Column(String(20), default='info')  # info, warning, error, critical
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship('User', back_populates='audit_logs', foreign_keys=[user_id])


class VerificationLog(Base):
    __tablename__ = 'verification_logs'
    id = Column(Integer, primary_key=True)
    evidence_hash = Column(String(64))
    verified_by_name = Column(String(150))
    verified_by_org = Column(String(150))
    result = Column(String(20))  # verified, tampered, not_found
    ip_address = Column(String(45))
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
