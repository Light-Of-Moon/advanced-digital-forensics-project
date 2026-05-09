"""Application entry point."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import create_app

if __name__ == '__main__':
    app = create_app()
    print("\n" + "="*60)
    print("  CipherChain Forensics - Digital Evidence System")
    print("="*60)
    print("  → http://localhost:5000")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
