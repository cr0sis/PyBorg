#!/usr/bin/env python3
"""
Test script to verify PyBorg setup is working correctly.
Run this before starting the bot to validate your configuration.
"""

import sys
from pathlib import Path

def test_imports():
    """Test that all core modules can be imported"""
    try:
        from core.config import BotConfig
        from core.database import BotDatabase  
        from core.plugin_system import get_plugin_manager
        print("✅ Core modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_config():
    """Test configuration loading"""
    try:
        from core.config import BotConfig
        networks_file = Path("networks.json")
        
        if not networks_file.exists():
            print("❌ networks.json not found. Copy networks.example.json to networks.json")
            return False
            
        config = BotConfig()  # Use default network
        print(f"✅ Configuration loaded - Network: {config.NETWORK}")
        print(f"   Host: {config.HOST}:{config.PORT}")
        print(f"   Channels: {config.CHANNELS}")
        print(f"   Prefix: {config.COMMAND_PREFIX}")
        return True
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

def test_database():
    """Test database system"""
    try:
        from core.database import BotDatabase
        from core.paths import ensure_directories, DATABASE_DIR
        
        # Ensure directories exist
        ensure_directories()
        
        db = BotDatabase('test_setup.db')
        print("✅ Database system working")
        print(f"   Database directory: {DATABASE_DIR}")
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def test_plugins():
    """Test plugin system"""
    try:
        from core.plugin_system import get_plugin_manager
        pm = get_plugin_manager('test_network', '!')
        print(f"✅ Plugin system loaded {len(pm.commands)} commands")
        return True
    except Exception as e:
        print(f"❌ Plugin error: {e}")
        return False

def test_paths():
    """Test path system and directory creation"""
    try:
        from core.paths import ensure_directories, DATA_DIR, DATABASE_DIR, LOG_DIR, BASE_DIR
        
        # Ensure directories exist
        ensure_directories()
        
        # Check that key directories exist
        if not DATA_DIR.exists():
            print(f"❌ Data directory not created: {DATA_DIR}")
            return False
            
        if not DATABASE_DIR.exists():
            print(f"❌ Database directory not created: {DATABASE_DIR}")
            return False
            
        if not LOG_DIR.exists():
            print(f"❌ Log directory not created: {LOG_DIR}")
            return False
        
        print("✅ Path system working")
        print(f"   Base directory: {BASE_DIR}")
        print(f"   Data directory: {DATA_DIR}")
        print(f"   Database directory: {DATABASE_DIR}")
        return True
        
    except Exception as e:
        print(f"❌ Path system error: {e}")
        return False

def test_environment():
    """Test environment variables"""
    import os
    env_file = Path(".env")
    
    if not env_file.exists():
        print("⚠️  .env file not found. Copy .env.example to .env")
        print("   Bot will work but AI features require GEMINI_API_KEY")
    
    gemini_key = os.getenv('GEMINI_API_KEY')
    if gemini_key:
        print("✅ GEMINI_API_KEY found - AI features will work")
    else:
        print("⚠️  GEMINI_API_KEY not set - AI features disabled")
    
    return True

def main():
    print("🧪 PyBorg Setup Test")
    print("=" * 40)
    
    tests = [
        ("Imports", test_imports),
        ("Paths", test_paths),
        ("Environment", test_environment), 
        ("Configuration", test_config),
        ("Database", test_database),
        ("Plugins", test_plugins)
    ]
    
    passed = 0
    for test_name, test_func in tests:
        print(f"\n📋 Testing {test_name}...")
        if test_func():
            passed += 1
        else:
            print(f"   Test failed: {test_name}")
    
    print(f"\n🎯 Test Results: {passed}/{len(tests)} passed")
    
    if passed == len(tests):
        print("🎉 All tests passed! PyBorg is ready to run.")
        print("\n🚀 Start the bot with:")
        print("   python bot_v2.py")
        return 0
    else:
        print("❗ Some tests failed. Check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())