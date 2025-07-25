#!/usr/bin/env python3
"""
YaraMan Launcher Script

Simple launcher for the YaraMan application with basic dependency checking.
"""

import sys
import subprocess
import os

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import flask
        import yara
        print("✓ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Please install dependencies with: pip install -r requirements.txt")
        return False

def check_yara_system():
    """Check if YARA is properly installed on the system"""
    try:
        import yara
        # Try to compile a simple rule to test YARA functionality
        yara.compile(source='rule test { condition: true }')
        print("✓ YARA is working correctly")
        return True
    except Exception as e:
        print(f"✗ YARA error: {e}")
        print("Please ensure YARA is properly installed on your system")
        return False

def main():
    """Main launcher function"""
    print("🛡️  Starting YaraMan - YARA Rules Manager & File Scanner")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("✗ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check YARA
    if not check_yara_system():
        sys.exit(1)
    
    # Start the application
    print("\n🚀 Starting YaraMan server...")
    print("📍 Open your browser to: http://localhost:5002")
    print("🔧 Press Ctrl+C to stop the server")
    print("=" * 60)
    
    try:
        from app import app
        app.run(debug=False, host='0.0.0.0', port=5002)
    except KeyboardInterrupt:
        print("\n👋 YaraMan server stopped")
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()