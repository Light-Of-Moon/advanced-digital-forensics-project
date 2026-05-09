"""Database initialization and seeding."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from backend.models import Base, User, Case, CaseAssignment
from backend.config import config
from backend.auth import hash_password
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

engine = create_engine(
    config.DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

SessionLocal = scoped_session(sessionmaker(bind=engine))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create all tables and seed default users."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed admin user
        if not db.query(User).filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@forensics.gov',
                password_hash=hash_password('Admin@2024!'),
                role='admin',
                full_name='System Administrator',
                department='IT Security',
                badge_number='ADM-001',
                is_active=True
            )
            db.add(admin)
            db.flush()

            # Seed investigator
            inv = User(
                username='investigator1',
                email='inv1@forensics.gov',
                password_hash=hash_password('Invest@2024!'),
                role='investigator',
                full_name='Agent John Harper',
                department='Digital Forensics Unit',
                badge_number='INV-001',
                is_active=True,
                created_by=admin.id
            )
            db.add(inv)
            db.flush()

            # Seed analyst
            analyst = User(
                username='analyst1',
                email='analyst1@forensics.gov',
                password_hash=hash_password('Analyst@2024!'),
                role='analyst',
                full_name='Dr. Sarah Chen',
                department='Forensic Analysis Lab',
                badge_number='ANL-001',
                is_active=True,
                created_by=admin.id
            )
            db.add(analyst)
            db.flush()

            # Create a sample case
            case = Case(
                case_number='CASE-2024-0001',
                title='Operation Digital Shield',
                description='Investigation into alleged corporate data breach and evidence tampering.',
                status='active',
                priority='critical',
                location='New York, NY',
                incident_date=datetime(2024, 1, 15),
                created_by=admin.id
            )
            db.add(case)
            db.flush()

            # Assign investigator and analyst to case
            assign_inv = CaseAssignment(
                case_id=case.id,
                user_id=inv.id,
                role_in_case='Lead Investigator',
                assigned_by=admin.id
            )
            assign_analyst = CaseAssignment(
                case_id=case.id,
                user_id=analyst.id,
                role_in_case='Forensic Analyst',
                assigned_by=admin.id
            )
            db.add_all([assign_inv, assign_analyst])

            # Seed guest account (for public verification)
            guest = User(
                username='guest1',
                email='guest@external.org',
                password_hash=hash_password('Guest@2024!'),
                role='guest',
                full_name='External Verifier',
                department='Third Party',
                badge_number='GST-001',
                is_active=True,
                created_by=admin.id
            )
            db.add(guest)

            db.commit()
            logger.info("Database seeded successfully.")
            print("\n[+] Default accounts created:")
            print("   Admin:        admin / Admin@2024!")
            print("   Investigator: investigator1 / Invest@2024!")
            print("   Analyst:      analyst1 / Analyst@2024!")
            print("   Guest:        guest1 / Guest@2024!\n")
        else:
            logger.info("Database already initialized.")
    except Exception as e:
        db.rollback()
        logger.error(f"Database seed error: {e}")
        raise
    finally:
        db.close()
