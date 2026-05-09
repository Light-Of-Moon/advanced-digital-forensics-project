"""Main Flask application with all API routes."""
import os
import sys
import json
import uuid
import hashlib
import logging
import bleach
from datetime import datetime
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, send_from_directory, g, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import joinedload
import io

from backend.config import config
from backend.database import init_db, SessionLocal
from backend.models import User, Case, CaseAssignment, Evidence, CustodyLog, AuditLog, AnalystNote, VerificationLog
from backend.auth import (hash_password, verify_password, create_token,
                          get_current_user, login_required, roles_required, admin_required, investigator_required,
                          guest_or_login_required)
import backend.blockchain as bc
from backend.metadata_extractor import extract_metadata, compute_hashes

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# ─── App Setup ──────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}})

limiter = Limiter(key_func=get_remote_address, app=app,
                  default_limits=["2000 per 1 hour"])

os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(config.CERTIFICATES_FOLDER, exist_ok=True)

# ─── Helpers ────────────────────────────────────────────────────────────────
def sanitize(s):
    return bleach.clean(str(s)) if s else s

def log_audit(db, action, resource_type=None, resource_id=None, details=None, severity='info'):
    user = get_current_user()
    entry = AuditLog(
        user_id=user['sub'] if user else None,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:200],
        details=details,
        severity=severity
    )
    db.add(entry)

def allowed_file(filename):
    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    return ext in config.ALLOWED_EXTENSIONS

def evidence_to_dict(e):
    return {
        'id': e.id,
        'evidence_number': e.evidence_number,
        'case_id': e.case_id,
        'filename': e.filename,
        'original_filename': e.original_filename,
        'file_size': e.file_size,
        'file_size_human': e.file_size_human,
        'mime_type': e.mime_type,
        'sha256_hash': e.sha256_hash,
        'md5_hash': e.md5_hash,
        'evidence_type': e.evidence_type,
        'description': e.description,
        'location_found': e.location_found,
        'tags': e.tags,
        'status': e.status,
        'blockchain_tx': e.blockchain_tx,
        'blockchain_block': e.blockchain_block,
        'chain_of_custody_count': e.chain_of_custody_count,
        'uploaded_by': e.uploaded_by,
        'uploader_name': e.uploader.full_name if e.uploader else 'Unknown',
        'created_at': e.created_at.isoformat() if e.created_at else None,
    }

def user_to_dict(u, include_sensitive=False):
    d = {
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'role': u.role,
        'full_name': u.full_name,
        'department': u.department,
        'badge_number': u.badge_number,
        'is_active': u.is_active,
        'last_login': u.last_login.isoformat() if u.last_login else None,
        'created_at': u.created_at.isoformat() if u.created_at else None,
    }
    return d

def case_to_dict(c, include_assignments=False):
    d = {
        'id': c.id,
        'case_number': c.case_number,
        'title': c.title,
        'description': c.description,
        'status': c.status,
        'priority': c.priority,
        'location': c.location,
        'incident_date': c.incident_date.isoformat() if c.incident_date else None,
        'created_by': c.created_by,
        'creator_name': c.creator.full_name if c.creator else 'Unknown',
        'created_at': c.created_at.isoformat() if c.created_at else None,
        'evidence_count': len(c.evidence) if c.evidence else 0,
    }
    if include_assignments:
        d['assignments'] = [{
            'user_id': a.user_id,
            'full_name': a.user.full_name if a.user else 'Unknown',
            'username': a.user.username if a.user else '',
            'role_in_case': a.role_in_case,
        } for a in c.assignments]
    return d

# ─── Serve SPA ──────────────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend')
    if path and os.path.exists(os.path.join(frontend_dir, path)):
        return send_from_directory(frontend_dir, path)
    return send_from_directory(frontend_dir, 'index.html')

# ─── AUTH ────────────────────────────────────────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("15 per minute")
def login():
    data = request.get_json() or {}
    username = sanitize(data.get('username', '').strip())
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    db = SessionLocal()
    try:
        user = db.query(User).filter(
            (User.username == username) | (User.email == username)
        ).first()
        if not user or not user.is_active or not verify_password(password, user.password_hash):
            log_audit(db, 'LOGIN_FAILED', details=f'Failed login for: {username}', severity='warning')
            db.commit()
            return jsonify({'error': 'Invalid credentials'}), 401

        user.last_login = datetime.utcnow()
        log_audit(db, 'LOGIN_SUCCESS', resource_type='user', resource_id=user.id)
        db.commit()
        token = create_token(user.id, user.role, user.username)
        return jsonify({
            'token': token,
            'user': user_to_dict(user),
            'message': 'Login successful'
        })
    finally:
        db.close()


@app.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    user_data = g.current_user
    db = SessionLocal()
    try:
        user = db.query(User).get(user_data['sub'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'user': user_to_dict(user)})
    finally:
        db.close()

# ─── USERS (Admin) ──────────────────────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        return jsonify({'users': [user_to_dict(u) for u in users]})
    finally:
        db.close()

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json() or {}
    required = ['username', 'email', 'password', 'role']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    if data['role'] not in ('admin', 'investigator', 'analyst', 'viewer', 'guest'):
        return jsonify({'error': 'Role must be admin, investigator, analyst, viewer, or guest'}), 400

    db = SessionLocal()
    try:
        if db.query(User).filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists'}), 409
        if db.query(User).filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists'}), 409

        user = User(
            username=sanitize(data['username']),
            email=sanitize(data['email']),
            password_hash=hash_password(data['password']),
            role=data['role'],
            full_name=sanitize(data.get('full_name', '')),
            department=sanitize(data.get('department', '')),
            badge_number=sanitize(data.get('badge_number', '')),
            is_active=True,
            created_by=g.current_user['sub']
        )
        db.add(user)
        log_audit(db, 'USER_CREATED', 'user', None, f'Created user: {user.username}')
        db.commit()
        return jsonify({'user': user_to_dict(user), 'message': 'User created successfully'}), 201
    finally:
        db.close()

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    data = request.get_json() or {}
    db = SessionLocal()
    try:
        user = db.query(User).get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if 'role' in data and data['role'] in ('admin', 'investigator', 'analyst', 'viewer', 'guest'):
            user.role = data['role']
        if 'is_active' in data:
            user.is_active = bool(data['is_active'])
        if 'full_name' in data:
            user.full_name = sanitize(data['full_name'])
        if 'department' in data:
            user.department = sanitize(data['department'])
        if 'badge_number' in data:
            user.badge_number = sanitize(data['badge_number'])
        if 'password' in data and data['password']:
            user.password_hash = hash_password(data['password'])

        log_audit(db, 'USER_UPDATED', 'user', user_id)
        db.commit()
        return jsonify({'user': user_to_dict(user), 'message': 'User updated'})
    finally:
        db.close()

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    if user_id == g.current_user['sub']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    db = SessionLocal()
    try:
        user = db.query(User).get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        uname = user.username
        db.delete(user)
        log_audit(db, 'USER_DELETED', 'user', user_id, f'Deleted: {uname}', 'warning')
        db.commit()
        return jsonify({'message': 'User deleted'})
    finally:
        db.close()

# ─── CASES ──────────────────────────────────────────────────────────────────
@app.route('/api/cases', methods=['GET'])
@login_required
def list_cases():
    user = g.current_user
    db = SessionLocal()
    try:
        if user['role'] in ('admin',):
            cases = db.query(Case).options(
                joinedload(Case.creator), joinedload(Case.assignments)
            ).order_by(Case.created_at.desc()).all()
        else:
            assigned_case_ids = [
                a.case_id for a in db.query(CaseAssignment).filter_by(user_id=user['sub']).all()
            ]
            created_case_ids = [
                c.id for c in db.query(Case).filter_by(created_by=user['sub']).all()
            ]
            all_case_ids = list(set(assigned_case_ids + created_case_ids))
            cases = db.query(Case).options(
                joinedload(Case.creator), joinedload(Case.assignments)
            ).filter(Case.id.in_(all_case_ids) if all_case_ids else Case.id == -1).order_by(Case.created_at.desc()).all()

        return jsonify({'cases': [case_to_dict(c, include_assignments=True) for c in cases]})
    finally:
        db.close()

@app.route('/api/cases', methods=['POST'])
@investigator_required
def create_case():
    data = request.get_json() or {}
    required = ['title']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    db = SessionLocal()
    try:
        case_number = f"CASE-{datetime.utcnow().year}-{str(uuid.uuid4())[:8].upper()}"
        case = Case(
            case_number=case_number,
            title=sanitize(data['title']),
            description=sanitize(data.get('description', '')),
            status=data.get('status', 'open'),
            priority=data.get('priority', 'medium'),
            location=sanitize(data.get('location', '')),
            incident_date=datetime.fromisoformat(data['incident_date']) if data.get('incident_date') else None,
            created_by=g.current_user['sub']
        )
        db.add(case)
        db.flush()

        # Auto-assign creator
        assignment = CaseAssignment(
            case_id=case.id, user_id=g.current_user['sub'],
            role_in_case='Lead Investigator', assigned_by=g.current_user['sub']
        )
        db.add(assignment)

        # Detailed audit log for case creation
        detail_parts = [
            f'Case {case_number} created',
            f'Title: {case.title}',
            f'Priority: {case.priority}',
            f'Status: {case.status}',
        ]
        if case.location:
            detail_parts.append(f'Location: {case.location}')
        if case.incident_date:
            detail_parts.append(f'Incident date: {case.incident_date.strftime("%Y-%m-%d")}')
        log_audit(db, 'CASE_CREATED', 'case', case.id, ' | '.join(detail_parts))
        db.commit()

        case = db.query(Case).options(joinedload(Case.creator), joinedload(Case.assignments)).get(case.id)
        return jsonify({'case': case_to_dict(case, include_assignments=True), 'message': 'Case created'}), 201
    finally:
        db.close()

@app.route('/api/cases/<int:case_id>', methods=['GET'])
@login_required
def get_case(case_id):
    user = g.current_user
    db = SessionLocal()
    try:
        case = db.query(Case).options(
            joinedload(Case.creator),
            joinedload(Case.assignments).joinedload(CaseAssignment.user),
            joinedload(Case.evidence).joinedload(Evidence.uploader)
        ).get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
            
        # Access control
        if user['role'] != 'admin':
            is_assigned = any(a.user_id == user['sub'] for a in case.assignments)
            if not is_assigned and case.created_by != user['sub']:
                return jsonify({'error': 'Unauthorized to view this case'}), 403
                
        d = case_to_dict(case, include_assignments=True)
        d['evidence'] = [evidence_to_dict(e) for e in case.evidence]
        return jsonify({'case': d})
    finally:
        db.close()

@app.route('/api/cases/<int:case_id>/assign', methods=['POST'])
@investigator_required
def assign_user(case_id):
    data = request.get_json() or {}
    user_id = data.get('user_id')
    role_in_case = data.get('role_in_case', 'Team Member')
    if not user_id:
        return jsonify({'error': 'user_id required'}), 400

    db = SessionLocal()
    try:
        case = db.query(Case).get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        target = db.query(User).get(user_id)
        if not target:
            return jsonify({'error': 'User not found'}), 404
        existing = db.query(CaseAssignment).filter_by(case_id=case_id, user_id=user_id).first()
        if existing:
            existing.role_in_case = role_in_case
        else:
            db.add(CaseAssignment(case_id=case_id, user_id=user_id,
                                  role_in_case=role_in_case, assigned_by=g.current_user['sub']))
        log_audit(db, 'USER_ASSIGNED', 'case', case_id, f'User {user_id} → Case {case_id}')
        db.commit()
        return jsonify({'message': f'{target.full_name} assigned to case'})
    finally:
        db.close()

@app.route('/api/cases/<int:case_id>', methods=['PUT'])
@login_required
def update_case(case_id):
    data = request.get_json() or {}
    db = SessionLocal()
    try:
        case = db.query(Case).get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404

        # Track what changed for audit
        changes = []
        for field in ['title', 'description', 'status', 'priority', 'location']:
            if field in data:
                old_val = getattr(case, field, '') or ''
                new_val = sanitize(data[field]) or ''
                if old_val != new_val:
                    # Truncate long values for log readability
                    old_display = (old_val[:60] + '...') if len(old_val) > 60 else old_val
                    new_display = (new_val[:60] + '...') if len(new_val) > 60 else new_val
                    changes.append(f'{field}: "{old_display}" → "{new_display}"')
                setattr(case, field, sanitize(data[field]))
        if 'incident_date' in data and data['incident_date']:
            old_date = case.incident_date.strftime('%Y-%m-%d') if case.incident_date else 'none'
            case.incident_date = datetime.fromisoformat(data['incident_date'])
            new_date = case.incident_date.strftime('%Y-%m-%d')
            if old_date != new_date:
                changes.append(f'incident_date: {old_date} → {new_date}')
        case.updated_at = datetime.utcnow()

        # Build concise but informative log
        detail = f'Case {case.case_number} updated'
        if changes:
            detail += ' | ' + ' | '.join(changes)
        else:
            detail += ' (no field changes detected)'
        log_audit(db, 'CASE_UPDATED', 'case', case_id, detail)
        db.commit()
        return jsonify({'message': 'Case updated', 'case': case_to_dict(case)})
    finally:
        db.close()

# ─── EVIDENCE ───────────────────────────────────────────────────────────────
@app.route('/api/evidence/preview-metadata', methods=['POST'])
@investigator_required
@limiter.limit("60 per hour")
def preview_metadata():
    """Upload a file temporarily to extract full metadata for preview before submission."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400

    tmp_path = os.path.join('/tmp', f"meta_preview_{uuid.uuid4().hex}")
    try:
        file.save(tmp_path)
        meta = extract_metadata(tmp_path, file.filename)
        return jsonify({'metadata': meta})
    except Exception as e:
        return jsonify({'error': f'Metadata extraction failed: {str(e)}'}), 500
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.route('/api/evidence/upload', methods=['POST'])
@investigator_required
@limiter.limit("30 per hour")
def upload_evidence():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    case_id = request.form.get('case_id')
    if not case_id:
        return jsonify({'error': 'case_id is required'}), 400

    db = SessionLocal()
    try:
        case = db.query(Case).get(int(case_id))
        if not case:
            return jsonify({'error': 'Case not found'}), 404

        # Save file with unique name
        ext = os.path.splitext(file.filename)[1].lower()
        unique_name = f"{uuid.uuid4().hex}{ext}"
        filepath = os.path.join(config.UPLOAD_FOLDER, unique_name)
        file.save(filepath)

        # Extract metadata
        meta = extract_metadata(filepath, file.filename)
        sha256 = meta.get('sha256', '')
        md5 = meta.get('md5', '')

        if not sha256:
            os.remove(filepath)
            return jsonify({'error': 'Failed to compute hash'}), 500

        # Check for duplicate
        existing = db.query(Evidence).filter_by(sha256_hash=sha256).first()
        if existing:
            os.remove(filepath)
            return jsonify({'error': f'Duplicate evidence (hash already recorded as evidence #{existing.evidence_number})'}), 409

        # Register on blockchain
        evidence_number = f"EVD-{datetime.utcnow().year}-{str(uuid.uuid4())[:8].upper()}"
        bc_result = bc.register_evidence(str(case_id), sha256, 'UPLOAD', str(g.current_user['sub']))

        evidence_type = request.form.get('evidence_type', 'other')

        evidence = Evidence(
            evidence_number=evidence_number,
            case_id=int(case_id),
            filename=unique_name,
            original_filename=file.filename,
            file_size=meta.get('size', 0),
            file_size_human=meta.get('size_human', ''),
            mime_type=meta.get('mime_type', ''),
            sha256_hash=sha256,
            md5_hash=md5,
            evidence_type=evidence_type,
            description=sanitize(request.form.get('description', '')),
            location_found=sanitize(request.form.get('location_found', '')),
            tags=sanitize(request.form.get('tags', '')),
            status='verified' if bc_result.get('success') else 'pending',
            blockchain_tx=bc_result.get('tx_hash', ''),
            blockchain_block=bc_result.get('block_number'),
            chain_of_custody_count=1,
            uploaded_by=g.current_user['sub']
        )

        # Merge user-edited metadata overrides
        user_meta_raw = request.form.get('metadata_overrides', '')
        if user_meta_raw:
            try:
                user_overrides = json.loads(user_meta_raw)
                meta['user_notes'] = user_overrides.get('notes', '')
                if user_overrides.get('camera_override'):
                    meta.setdefault('camera', {})
                    meta['camera']['user_notes'] = user_overrides['camera_override']
                if user_overrides.get('gps_override'):
                    meta.setdefault('gps', {})
                    meta['gps']['user_notes'] = user_overrides['gps_override']
                if user_overrides.get('software_override'):
                    meta.setdefault('software', {})
                    meta['software']['user_notes'] = user_overrides['software_override']
                if user_overrides.get('editing_override'):
                    meta.setdefault('editing_analysis', {})
                    meta['editing_analysis']['user_notes'] = user_overrides['editing_override']
            except json.JSONDecodeError:
                pass

        evidence.metadata_json = json.dumps(meta)
        db.add(evidence)
        db.flush()

        # Custody log
        clog = CustodyLog(
            evidence_id=evidence.id,
            action='uploaded',
            to_user_id=g.current_user['sub'],
            ip_address=request.remote_addr,
            blockchain_tx=bc_result.get('tx_hash', ''),
            details=f'Initial upload. Hash: {sha256}'
        )
        db.add(clog)

        # Detailed evidence upload log
        ev_detail_parts = [
            f'{evidence_number} uploaded to case #{case_id}',
            f'File: {file.filename} ({meta.get("size_human", "")})',
            f'Type: {evidence_type}',
            f'SHA-256: {sha256[:16]}...',
            f'Blockchain: {"confirmed" if bc_result.get("success") else "pending"} (TX: {bc_result.get("tx_hash", "N/A")[:16]}...)',
        ]
        if request.form.get('description'):
            desc_preview = request.form.get('description', '')[:80]
            ev_detail_parts.append(f'Desc: {desc_preview}')
        log_audit(db, 'EVIDENCE_UPLOADED', 'evidence', evidence.id, ' | '.join(ev_detail_parts))
        db.commit()

        ev = db.query(Evidence).options(joinedload(Evidence.uploader)).get(evidence.id)
        return jsonify({
            'evidence': evidence_to_dict(ev),
            'blockchain': bc_result,
            'message': 'Evidence uploaded and registered on blockchain'
        }), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Upload error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()

def check_case_access(user, case):
    if user['role'] == 'admin': return True
    return any(a.user_id == user['sub'] for a in case.assignments) or case.created_by == user['sub']

@app.route('/api/evidence/<int:evidence_id>', methods=['GET'])
@login_required
def get_evidence(evidence_id):
    user = g.current_user
    db = SessionLocal()
    try:
        ev = db.query(Evidence).options(joinedload(Evidence.uploader), joinedload(Evidence.case).joinedload(Case.assignments)).get(evidence_id)
        if not ev:
            return jsonify({'error': 'Evidence not found'}), 404
        if ev.case and not check_case_access(user, ev.case):
            return jsonify({'error': 'Unauthorized to view this evidence'}), 403
        d = evidence_to_dict(ev)
        d['metadata'] = json.loads(ev.metadata_json) if ev.metadata_json else {}
        d['custody_logs'] = [{
            'id': cl.id, 'action': cl.action,
            'from_user_id': cl.from_user_id, 'to_user_id': cl.to_user_id,
            'ip_address': cl.ip_address, 'blockchain_tx': cl.blockchain_tx,
            'details': cl.details, 'timestamp': cl.timestamp.isoformat()
        } for cl in ev.custody_logs]
        return jsonify({'evidence': d})
    finally:
        db.close()

@app.route('/api/evidence/<int:evidence_id>/download', methods=['GET'])
@login_required
def download_evidence(evidence_id):
    user = g.current_user
    db = SessionLocal()
    try:
        ev = db.query(Evidence).options(joinedload(Evidence.case).joinedload(Case.assignments)).get(evidence_id)
        if not ev:
            return jsonify({'error': 'Evidence not found'}), 404
        if ev.case and not check_case_access(user, ev.case):
            return jsonify({'error': 'Unauthorized to download this evidence'}), 403
        filepath = os.path.join(config.UPLOAD_FOLDER, ev.filename)
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found on disk'}), 404
        log_audit(db, 'EVIDENCE_DOWNLOADED', 'evidence', evidence_id)
        db.commit()
        return send_file(filepath, as_attachment=True, download_name=ev.original_filename)
    finally:
        db.close()

@app.route('/api/evidence/<int:evidence_id>/transfer', methods=['POST'])
@investigator_required
def transfer_evidence(evidence_id):
    user = g.current_user
    data = request.get_json() or {}
    to_user_id = data.get('to_user_id')
    reason = sanitize(data.get('reason', ''))

    db = SessionLocal()
    try:
        ev = db.query(Evidence).options(joinedload(Evidence.case).joinedload(Case.assignments)).get(evidence_id)
        if not ev:
            return jsonify({'error': 'Evidence not found'}), 404
        if ev.case and not check_case_access(user, ev.case):
            return jsonify({'error': 'Unauthorized to transfer this evidence'}), 403
        target = db.query(User).get(to_user_id)
        if not target:
            return jsonify({'error': 'Target user not found'}), 404

        bc_result = bc.transfer_custody(ev.sha256_hash, str(g.current_user['sub']), str(to_user_id), reason)

        clog = CustodyLog(
            evidence_id=evidence_id,
            action='transferred',
            from_user_id=g.current_user['sub'],
            to_user_id=to_user_id,
            ip_address=request.remote_addr,
            blockchain_tx=bc_result.get('tx_hash', ''),
            details=f'Transfer reason: {reason}'
        )
        ev.chain_of_custody_count = (ev.chain_of_custody_count or 1) + 1
        ev.status = 'transferred'
        db.add(clog)
        transfer_detail = (
            f'{ev.evidence_number} transferred | '
            f'From: user #{g.current_user["sub"]} → To: {target.full_name} (#{to_user_id}) | '
            f'Reason: {reason[:100]}'
        )
        log_audit(db, 'EVIDENCE_TRANSFERRED', 'evidence', evidence_id, transfer_detail)
        db.commit()
        return jsonify({'message': f'Evidence transferred to {target.full_name}', 'blockchain': bc_result})
    finally:
        db.close()

@app.route('/api/evidence/<int:evidence_id>/verify', methods=['GET'])
@login_required
def verify_evidence_integrity(evidence_id):
    user = g.current_user
    db = SessionLocal()
    try:
        ev = db.query(Evidence).options(joinedload(Evidence.case).joinedload(Case.assignments)).get(evidence_id)
        if not ev:
            return jsonify({'error': 'Evidence not found'}), 404
        if ev.case and not check_case_access(user, ev.case):
            return jsonify({'error': 'Unauthorized to verify this evidence'}), 403

        # Re-hash the stored file
        filepath = os.path.join(config.UPLOAD_FOLDER, ev.filename)
        if not os.path.exists(filepath):
            return jsonify({'error': 'File missing on disk'}), 404

        hashes = compute_hashes(filepath)
        current_hash = hashes.get('sha256', '')
        is_tampered = current_hash != ev.sha256_hash

        bc_result = bc.verify_evidence(ev.sha256_hash)
        status = 'tampered' if is_tampered else ('verified' if bc_result['found'] else 'not_on_chain')

        if not is_tampered:
            ev.status = 'verified'
            db.commit()

        log_audit(db, 'EVIDENCE_VERIFIED', 'evidence', evidence_id, f'Result: {status}')
        db.commit()
        return jsonify({
            'evidence_id': evidence_id,
            'evidence_number': ev.evidence_number,
            'stored_hash': ev.sha256_hash,
            'current_hash': current_hash,
            'hashes_match': not is_tampered,
            'blockchain_found': bc_result['found'],
            'blockchain_record': bc_result.get('record', {}),
            'status': status,
            'verified': not is_tampered and bc_result['found']
        })
    finally:
        db.close()

# ─── ANALYST NOTES ──────────────────────────────────────────────────────────
@app.route('/api/evidence/<int:evidence_id>/notes', methods=['GET'])
@login_required
def get_notes(evidence_id):
    user = g.current_user
    db = SessionLocal()
    try:
        ev = db.query(Evidence).options(joinedload(Evidence.case).joinedload(Case.assignments)).get(evidence_id)
        if not ev:
            return jsonify({'error': 'Evidence not found'}), 404
        if ev.case and not check_case_access(user, ev.case):
            return jsonify({'error': 'Unauthorized to view this evidence'}), 403
            
        notes = db.query(AnalystNote).filter_by(evidence_id=evidence_id).all()
        return jsonify({'notes': [{
            'id': n.id, 'content': n.content,
            'classification': n.classification,
            'analyst_id': n.analyst_id,
            'created_at': n.created_at.isoformat()
        } for n in notes]})
    finally:
        db.close()

@app.route('/api/evidence/<int:evidence_id>/notes', methods=['POST'])
@roles_required('analyst')
def add_note(evidence_id):
    user = g.current_user
    data = request.get_json() or {}
    content = sanitize(data.get('content', ''))
    if not content:
        return jsonify({'error': 'Note content required'}), 400

    db = SessionLocal()
    try:
        ev = db.query(Evidence).options(joinedload(Evidence.case).joinedload(Case.assignments)).get(evidence_id)
        if not ev:
            return jsonify({'error': 'Evidence not found'}), 404
        if ev.case and not check_case_access(user, ev.case):
            return jsonify({'error': 'Unauthorized to add note to this evidence'}), 403
            
        note = AnalystNote(
            evidence_id=evidence_id,
            analyst_id=g.current_user['sub'],
            content=content,
            classification=data.get('classification', 'internal')
        )
        db.add(note)
        log_audit(db, 'NOTE_ADDED', 'evidence', evidence_id)
        db.commit()
        return jsonify({'note': {'id': note.id, 'content': note.content}, 'message': 'Note added'}), 201
    finally:
        db.close()

# ─── PUBLIC VERIFICATION (Guest Auth Required) ─────────────────────────────
@app.route('/api/public/verify', methods=['POST'])
@guest_or_login_required
@limiter.limit("20 per hour")
def public_verify():
    """Guest auth required. Upload a file to verify its integrity."""
    user = g.current_user
    verifier_name = sanitize(request.form.get('verifier_name', 'Anonymous'))
    verifier_org = sanitize(request.form.get('verifier_org', ''))

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400

    # Save temp file
    tmp_path = os.path.join('/tmp', f"verify_{uuid.uuid4().hex}")
    try:
        file.save(tmp_path)
        hashes = compute_hashes(tmp_path)
        sha256 = hashes.get('sha256', '')
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    if not sha256:
        return jsonify({'error': 'Failed to compute hash'}), 500

    # Check blockchain
    bc_result = bc.verify_evidence(sha256)

    db = SessionLocal()
    try:
        # Check database
        ev = db.query(Evidence).filter_by(sha256_hash=sha256).first()

        if ev and bc_result['found']:
            result = 'verified'
            status_text = '✅ VERIFIED — Evidence is authentic and untampered'
        elif ev and not bc_result['found']:
            result = 'verified_db_only'
            status_text = '⚠ FOUND IN DATABASE — Blockchain record pending'
        else:
            result = 'not_found'
            status_text = '❌ NOT FOUND — No matching evidence record'

        # Log verification
        vlog = VerificationLog(
            evidence_hash=sha256,
            verified_by_name=verifier_name,
            verified_by_org=verifier_org,
            result=result,
            ip_address=request.remote_addr,
            details=f'File: {file.filename} | Guest user #{user["sub"]} ({verifier_name})'
        )
        db.add(vlog)
        log_audit(db, 'PUBLIC_VERIFY_FILE', 'evidence', None,
                  f'Guest verified file: {file.filename} | Result: {result} | Hash: {sha256[:16]}...')
        db.commit()

        return jsonify({
            'hash': sha256,
            'result': result,
            'status_text': status_text,
            'found_in_database': ev is not None,
            'found_on_blockchain': bc_result['found'],
            'evidence_number': ev.evidence_number if ev else None,
            'case_id': ev.case_id if ev else None,
            'upload_date': ev.created_at.isoformat() if ev and ev.created_at else None,
            'blockchain_record': bc_result.get('record', {})
        })
    finally:
        db.close()

@app.route('/api/public/verify-hash', methods=['POST'])
@guest_or_login_required
@limiter.limit("30 per hour")
def public_verify_hash():
    """Verify by providing a hash string directly. Requires guest or staff auth."""
    data = request.get_json() or {}
    sha256 = data.get('hash', '').strip().lower()
    if len(sha256) != 64:
        return jsonify({'error': 'Invalid SHA-256 hash (must be 64 hex chars)'}), 400

    bc_result = bc.verify_evidence(sha256)
    db = SessionLocal()
    try:
        ev = db.query(Evidence).filter_by(sha256_hash=sha256).first()
        if ev:
            result = 'verified' if bc_result['found'] else 'db_only'
            status_text = '✅ VERIFIED — Hash matches a registered evidence record'
        else:
            result = 'not_found'
            status_text = '❌ NOT FOUND — Hash not in system'
        log_audit(db, 'PUBLIC_VERIFY_HASH', 'evidence', None,
                  f'Hash lookup: {sha256[:16]}... | Result: {result}')
        db.commit()
        return jsonify({
            'hash': sha256,
            'result': result,
            'status_text': status_text,
            'evidence_number': ev.evidence_number if ev else None,
            'blockchain_found': bc_result['found']
        })
    finally:
        db.close()

# ─── CERTIFICATES ────────────────────────────────────────────────────────────
@app.route('/api/certificate/<int:evidence_id>', methods=['GET'])
@login_required
def download_certificate(evidence_id):
    user = g.current_user
    db = SessionLocal()
    try:
        ev = db.query(Evidence).options(
            joinedload(Evidence.uploader), joinedload(Evidence.case).joinedload(Case.assignments)
        ).get(evidence_id)
        if not ev:
            return jsonify({'error': 'Evidence not found'}), 404
        if ev.case and not check_case_access(user, ev.case):
            return jsonify({'error': 'Unauthorized to view this certificate'}), 403

        from backend.certificate import generate_certificate
        pdf_bytes = generate_certificate(
            evidence={
                'id': ev.id, 'evidence_number': ev.evidence_number,
                'original_filename': ev.original_filename, 'file_size_human': ev.file_size_human,
                'sha256_hash': ev.sha256_hash, 'md5_hash': ev.md5_hash,
                'evidence_type': ev.evidence_type, 'status': ev.status,
                'blockchain_tx': ev.blockchain_tx, 'blockchain_block': ev.blockchain_block,
                'created_at': ev.created_at.isoformat() if ev.created_at else '',
            },
            case={
                'case_number': ev.case.case_number if ev.case else 'N/A',
                'title': ev.case.title if ev.case else 'N/A',
            },
            investigator={
                'full_name': ev.uploader.full_name if ev.uploader else 'N/A',
                'badge_number': ev.uploader.badge_number if ev.uploader else 'N/A',
                'department': ev.uploader.department if ev.uploader else 'N/A',
            }
        )
        log_audit(db, 'CERTIFICATE_DOWNLOADED', 'evidence', evidence_id)
        db.commit()
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"certificate_{ev.evidence_number}.pdf"
        )
    finally:
        db.close()

# ─── AUDIT & DASHBOARD ──────────────────────────────────────────────────────
@app.route('/api/audit/logs', methods=['GET'])
@admin_required
def audit_logs():
    db = SessionLocal()
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        severity = request.args.get('severity')

        q = db.query(AuditLog).options(joinedload(AuditLog.user))
        if severity:
            q = q.filter_by(severity=severity)
        total = q.count()
        logs = q.order_by(AuditLog.timestamp.desc()).offset((page-1)*per_page).limit(per_page).all()

        return jsonify({
            'logs': [{
                'id': l.id, 'action': l.action,
                'username': l.user.username if l.user else 'System',
                'full_name': l.user.full_name if l.user else 'System',
                'resource_type': l.resource_type, 'resource_id': l.resource_id,
                'ip_address': l.ip_address, 'details': l.details,
                'severity': l.severity,
                'timestamp': l.timestamp.isoformat()
            } for l in logs],
            'total': total, 'page': page, 'pages': (total + per_page - 1) // per_page
        })
    finally:
        db.close()

@app.route('/api/audit/logs/<int:log_id>', methods=['DELETE'])
@admin_required
def delete_audit_log(log_id):
    db = SessionLocal()
    try:
        log = db.query(AuditLog).get(log_id)
        if not log:
            return jsonify({'error': 'Log not found'}), 404
        db.delete(log)
        db.commit()
        return jsonify({'message': 'System log deleted successfully'})
    finally:
        db.close()

@app.route('/api/audit/logs/clear', methods=['DELETE'])
@admin_required
def clear_audit_logs():
    db = SessionLocal()
    try:
        db.query(AuditLog).delete()
        db.commit()
        return jsonify({'message': 'All system logs cleared successfully'})
    finally:
        db.close()

@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    user = g.current_user
    db = SessionLocal()
    try:
        if user['role'] == 'admin':
            cases_q = db.query(Case)
            ev_q = db.query(Evidence)
            total_users = db.query(User).count()
        else:
            total_users = 1
            assigned_case_ids = [a.case_id for a in db.query(CaseAssignment).filter_by(user_id=user['sub']).all()]
            created_case_ids = [c.id for c in db.query(Case).filter_by(created_by=user['sub']).all()]
            all_case_ids = list(set(assigned_case_ids + created_case_ids))
            
            cases_q = db.query(Case).filter(Case.id.in_(all_case_ids) if all_case_ids else Case.id == -1)
            ev_q = db.query(Evidence).filter(Evidence.case_id.in_(all_case_ids) if all_case_ids else Evidence.case_id == -1)

        total_cases = cases_q.count()
        total_evidence = ev_q.count()
        verified = ev_q.filter(Evidence.status == 'verified').count()
        tampered = ev_q.filter(Evidence.status == 'tampered').count()
        pending = ev_q.filter(Evidence.status == 'pending').count()
        open_cases = cases_q.filter(Case.status == 'open').count()
        active_cases = cases_q.filter(Case.status == 'active').count()

        # Evidence by type
        from sqlalchemy import func
        if user['role'] == 'admin':
            type_counts = db.query(Evidence.evidence_type, func.count(Evidence.id)).group_by(Evidence.evidence_type).all()
        else:
            type_counts = db.query(Evidence.evidence_type, func.count(Evidence.id))\
                .filter(Evidence.case_id.in_(all_case_ids) if all_case_ids else Evidence.case_id == -1)\
                .group_by(Evidence.evidence_type).all()

        chain_status = bc.get_chain_status()

        return jsonify({
            'total_users': total_users,
            'total_cases': total_cases,
            'total_evidence': total_evidence,
            'verified_evidence': verified,
            'tampered_evidence': tampered,
            'pending_evidence': pending,
            'open_cases': open_cases,
            'active_cases': active_cases,
            'evidence_by_type': {t: c for t, c in type_counts},
            'blockchain': chain_status
        })
    finally:
        db.close()

@app.route('/api/dashboard/recent', methods=['GET'])
@login_required
def dashboard_recent():
    user = g.current_user
    db = SessionLocal()
    try:
        if user['role'] == 'admin':
            recent_evidence = db.query(Evidence).options(joinedload(Evidence.uploader)).order_by(Evidence.created_at.desc()).limit(8).all()
            recent_cases = db.query(Case).options(joinedload(Case.creator)).order_by(Case.created_at.desc()).limit(5).all()
            
            # For admin, see all meaningful system activity
            recent_logs = db.query(AuditLog).options(joinedload(AuditLog.user))\
                .filter(AuditLog.action.in_(['CASE_CREATED', 'CASE_UPDATED', 'EVIDENCE_UPLOADED', 'ASSIGNMENT_ADDED', 'GUEST_VERIFIED', 'VERIFICATION_SUCCESS', 'VERIFICATION_FAILED']))\
                .order_by(AuditLog.timestamp.desc()).limit(15).all()
            recent_verifs = db.query(VerificationLog).order_by(VerificationLog.timestamp.desc()).limit(10).all()
        else:
            assigned_case_ids = [a.case_id for a in db.query(CaseAssignment).filter_by(user_id=user['sub']).all()]
            created_case_ids = [c.id for c in db.query(Case).filter_by(created_by=user['sub']).all()]
            all_case_ids = list(set(assigned_case_ids + created_case_ids))
            
            recent_evidence = db.query(Evidence).options(joinedload(Evidence.uploader))\
                .filter(Evidence.case_id.in_(all_case_ids) if all_case_ids else Evidence.case_id == -1)\
                .order_by(Evidence.created_at.desc()).limit(8).all()
            
            recent_cases = db.query(Case).options(joinedload(Case.creator))\
                .filter(Case.id.in_(all_case_ids) if all_case_ids else Case.id == -1)\
                .order_by(Case.created_at.desc()).limit(5).all()
                
            # See activity on assigned cases or own actions
            recent_logs = db.query(AuditLog).options(joinedload(AuditLog.user))\
                .filter(AuditLog.action.in_(['CASE_CREATED', 'CASE_UPDATED', 'EVIDENCE_UPLOADED', 'ASSIGNMENT_ADDED']))\
                .filter((AuditLog.resource_id.in_(all_case_ids)) | (AuditLog.user_id == user['sub']))\
                .order_by(AuditLog.timestamp.desc()).limit(15).all()
            
            recent_verifs = []

        all_activity = []
        for l in recent_logs:
            all_activity.append({
                'action': l.action, 'severity': l.severity,
                'user': l.user.username if l.user else 'System',
                'resource_type': l.resource_type,
                'timestamp': l.timestamp
            })
        for v in recent_verifs:
            org_str = f" ({v.verified_by_org})" if v.verified_by_org else ""
            user_str = f"{v.verified_by_name}{org_str}".strip()
            if not user_str or user_str == 'Anonymous':
                user_str = 'Third-Party'
            
            all_activity.append({
                'action': f"VERIFICATION_{v.result.upper()}",
                'severity': 'highlight' if 'verified' in v.result else 'error',
                'user': user_str,
                'resource_type': 'Evidence',
                'timestamp': v.timestamp
            })
            
        all_activity.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Format timestamps
        recent_activity_formatted = []
        for a in all_activity[:15]:
            a['timestamp'] = a['timestamp'].isoformat()
            recent_activity_formatted.append(a)

        return jsonify({
            'recent_evidence': [evidence_to_dict(e) for e in recent_evidence],
            'recent_cases': [case_to_dict(c) for c in recent_cases],
            'recent_activity': recent_activity_formatted
        })
    finally:
        db.close()

@app.route('/api/blockchain/status', methods=['GET'])
@login_required
def blockchain_status():
    return jsonify(bc.get_chain_status())

@app.route('/api/system/activity', methods=['GET'])
@admin_required
def system_activity():
    """Admin system monitoring."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        # Logins per day (last 7 days)
        active_users = db.query(User).filter_by(is_active=True).count()
        total_audit = db.query(AuditLog).count()
        warnings = db.query(AuditLog).filter_by(severity='warning').count()
        errors = db.query(AuditLog).filter_by(severity='error').count()
        return jsonify({
            'active_users': active_users,
            'total_audit_events': total_audit,
            'warnings': warnings,
            'errors': errors,
        })
    finally:
        db.close()

# ─── INIT ────────────────────────────────────────────────────────────────────
def create_app():
    init_db()
    return app

if __name__ == '__main__':
    create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
