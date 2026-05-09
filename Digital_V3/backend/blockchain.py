"""
Custom Python Blockchain implementation.
Ensures immutability, SHA-256 hashing, full chain validation, and chain of custody logging.
"""
import os
import sys
import json
import hashlib
import logging
from datetime import datetime
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.config import config

logger = logging.getLogger(__name__)

class Block:
    def __init__(self, index: int, timestamp: str, evidence_hash: str, previous_hash: str, action_type: str, user_id: str, role: str, details: str = ""):
        self.index = index
        self.timestamp = timestamp
        self.evidence_hash = evidence_hash
        self.previous_hash = previous_hash
        self.action_type = action_type
        self.user_id = user_id
        self.role = role
        self.details = details
        self.current_hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Calculate the SHA-256 hash of the block."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
            "action_type": self.action_type,
            "user_id": self.user_id,
            "role": self.role,
            "details": self.details
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "action_type": self.action_type,
            "user_id": self.user_id,
            "role": self.role,
            "details": self.details
        }

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        # Create the genesis block
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(
            index=0,
            timestamp=datetime.utcnow().isoformat(),
            evidence_hash="0" * 64,
            previous_hash="0" * 64,
            action_type="GENESIS",
            user_id="SYSTEM",
            role="SYSTEM",
            details="Genesis Block"
        )
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, evidence_hash: str, action_type: str, user_id: str, role: str = "Unknown", details: str = "") -> Block:
        previous_block = self.get_latest_block()
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=datetime.utcnow().isoformat(),
            evidence_hash=evidence_hash,
            previous_hash=previous_block.current_hash,
            action_type=action_type,
            user_id=user_id,
            role=role,
            details=details
        )
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Re-verify hash calculation
            if current_block.current_hash != current_block.calculate_hash():
                logger.error(f"Chain corrupted at block {current_block.index}: invalid hash.")
                return False

            # Verify chain link
            if current_block.previous_hash != previous_block.current_hash:
                logger.error(f"Chain corrupted at block {current_block.index}: invalid previous hash.")
                return False

        return True

    def find_evidence_blocks(self, evidence_hash: str) -> List[Dict]:
        """Find all blocks related to a specific evidence hash."""
        return [block.to_dict() for block in self.chain if block.evidence_hash == evidence_hash]

# Global singleton blockchain instance
_blockchain = Blockchain()

def is_connected() -> bool:
    return True

def get_chain_status() -> dict:
    valid = _blockchain.is_chain_valid()
    return {
        'connected': True,
        'mode': 'custom_python',
        'block_number': len(_blockchain.chain) - 1,
        'record_count': len(_blockchain.chain),
        'chain_valid': valid,
        'note': 'Custom Python Blockchain active'
    }

def register_evidence(case_id: str, evidence_hash: str, action_type: str, user_id: str, role: str = "Unknown") -> dict:
    # First verify if it's already uploaded (to prevent duplicates)
    existing = _blockchain.find_evidence_blocks(evidence_hash)
    if any(b['action_type'] == 'UPLOAD' for b in existing):
        return {'success': False, 'error': 'Evidence already registered on blockchain'}

    block = _blockchain.add_block(
        evidence_hash=evidence_hash,
        action_type=action_type,
        user_id=user_id,
        role=role,
        details=f"Case ID: {case_id}"
    )
    return {'success': True, 'tx_hash': block.current_hash, 'block_number': block.index, 'mode': 'custom_python'}

def verify_evidence(evidence_hash: str) -> dict:
    blocks = _blockchain.find_evidence_blocks(evidence_hash)
    if not blocks:
        return {'found': False, 'record': {}, 'mode': 'custom_python'}
    
    # Check if the chain is actually valid up to this point
    is_valid = _blockchain.is_chain_valid()
    if not is_valid:
        return {'found': False, 'error': 'Blockchain integrity compromised', 'mode': 'custom_python'}

    # Return the first upload block as the main record
    upload_block = next((b for b in blocks if b['action_type'] == 'UPLOAD'), blocks[-1])
    return {'found': True, 'record': upload_block, 'history': blocks, 'mode': 'custom_python'}

def transfer_custody(evidence_hash: str, from_user: str, to_user: str, reason: str, role: str = "Unknown") -> dict:
    blocks = _blockchain.find_evidence_blocks(evidence_hash)
    if not blocks:
        return {'success': False, 'error': 'Evidence not found on chain'}

    block = _blockchain.add_block(
        evidence_hash=evidence_hash,
        action_type="TRANSFER",
        user_id=from_user,
        role=role,
        details=f"Transferred to {to_user}. Reason: {reason}"
    )
    return {'success': True, 'tx_hash': block.current_hash, 'block_number': block.index, 'mode': 'custom_python'}

def log_action(evidence_hash: str, action_type: str, user_id: str, role: str, details: str = "") -> dict:
    """General action logging on the blockchain (e.g. view, analyze)."""
    block = _blockchain.add_block(
        evidence_hash=evidence_hash,
        action_type=action_type,
        user_id=user_id,
        role=role,
        details=details
    )
    return {'success': True, 'tx_hash': block.current_hash, 'block_number': block.index, 'mode': 'custom_python'}
