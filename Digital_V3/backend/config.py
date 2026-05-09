"""Application configuration."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'forensic-blockchain-secret-key-2024-xK9mPqRs')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-forensic-secret-2024-Nv3LwQtY')
    JWT_EXPIRY_HOURS = 8

    # Database
    DATABASE_URL = f"sqlite:///{os.path.join(ROOT_DIR, 'forensics.db')}"

    # File uploads
    UPLOAD_FOLDER = os.path.join(ROOT_DIR, 'uploads')
    CERTIFICATES_FOLDER = os.path.join(ROOT_DIR, 'certificates')
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp',
        'doc', 'docx', 'xls', 'xlsx', 'csv', 'zip', 'tar', 'gz',
        'pcap', 'pcapng', 'cap', 'log', 'json', 'xml',
        'mp4', 'avi', 'mov', 'mkv', 'mp3', 'wav',
        'exe', 'dll', 'bin', 'iso', 'img', 'db', 'sqlite'
    }

    # Blockchain (Ganache)
    BLOCKCHAIN_RPC = os.environ.get('BLOCKCHAIN_RPC', 'http://127.0.0.1:7545')
    CONTRACT_CONFIG = os.path.join(ROOT_DIR, 'contract_config.json')

    # Rate limiting
    RATE_LIMIT_DEFAULT = "200 per day"
    RATE_LIMIT_LOGIN = "10 per minute"

    # CORS
    CORS_ORIGINS = ["http://localhost:5000", "http://127.0.0.1:5000"]

config = Config()
