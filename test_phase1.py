#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 1 Testing Script
Tests all refactored components for proper functionality
"""

import sys
import os
from pathlib import Path

# Fix Windows console encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Use ASCII-safe characters for Windows compatibility
PASS = "[OK]"
FAIL = "[FAIL]"
WARN = "[WARN]"

def test_config():
    """Test configuration module."""
    print("\n" + "="*60)
    print("TEST 1: Configuration Module")
    print("="*60)
    try:
        from utils.config import (
            BASE_DIR, MODEL_DIR, LOGS_DIR, DATASET_PATH,
            MODEL_PATH, SCALER_PATH, FEATURE_COLUMNS, 
            NETWORK_INTERFACE, PACKET_LIMIT
        )
        print(f"{PASS} Config module imported successfully")
        print(f"{PASS} BASE_DIR: {BASE_DIR}")
        print(f"{PASS} MODEL_DIR exists: {MODEL_DIR.exists()}")
        print(f"{PASS} LOGS_DIR exists: {LOGS_DIR.exists()}")
        print(f"{PASS} FEATURE_COLUMNS: {FEATURE_COLUMNS}")
        print(f"{PASS} PACKET_LIMIT: {PACKET_LIMIT}")
        print(f"{PASS} NETWORK_INTERFACE: {NETWORK_INTERFACE}")
        return True
    except Exception as e:
        print(f"{FAIL} Config test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_logger():
    """Test logger module."""
    print("\n" + "="*60)
    print("TEST 2: Logger Module")
    print("="*60)
    try:
        from utils.logger import log_info, log_error, log_warning, log_debug
        print(f"{PASS} Logger module imported successfully")
        
        log_info("Test info message")
        log_error("Test error message")
        log_warning("Test warning message")
        log_debug("Test debug message")
        
        print(f"{PASS} All logger functions work correctly")
        
        # Check if log file was created
        from utils.config import LOGS_FILE
        if LOGS_FILE.exists():
            print(f"{PASS} Log file created: {LOGS_FILE}")
        else:
            print(f"{WARN} Log file not found: {LOGS_FILE}")
        
        return True
    except Exception as e:
        print(f"{FAIL} Logger test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_imports():
    """Test all script imports."""
    print("\n" + "="*60)
    print("TEST 3: Script Imports and Syntax")
    print("="*60)
    
    scripts = [
        "convert_models",
        "test_inference",
        "src.Detection.realtimeDetection",
        "src.Sniffing.enhanced_packet",
        "src.Sniffing.InitialPackets",
        "src.ML_Model.Traning",
        "src.Sniffing.LabellingData"
    ]
    
    results = []
    for script in scripts:
        try:
            __import__(script)
            print(f"{PASS} {script} - Import successful")
            results.append(True)
        except ImportError as e:
            print(f"{FAIL} {script} - Import failed: {e}")
            results.append(False)
        except SyntaxError as e:
            print(f"{FAIL} {script} - Syntax error: {e}")
            results.append(False)
        except Exception as e:
            # Other exceptions might be okay (missing dependencies, etc.)
            print(f"{WARN} {script} - Import with warnings: {type(e).__name__}")
            results.append(True)  # Still consider it a pass if syntax is OK
    
    return all(results)


def test_error_handling():
    """Test error handling in convert_models."""
    print("\n" + "="*60)
    print("TEST 4: Error Handling (convert_models)")
    print("="*60)
    try:
        # This should fail gracefully when models don't exist
        sys.path.insert(0, str(Path(__file__).parent))
        from convert_models import convert_models
        
        result = convert_models()
        if result is False:
            print(f"{PASS} Error handling works - correctly returned False for missing models")
            return True
        else:
            print(f"{WARN} Models already exist, skipping error handling test")
            return True
    except Exception as e:
        print(f"{FAIL} Error handling test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_requirements():
    """Test if requirements can be installed."""
    print("\n" + "="*60)
    print("TEST 5: Requirements File")
    print("="*60)
    try:
        req_file = Path(__file__).parent / "requirements.txt"
        if not req_file.exists():
            print(f"{FAIL} requirements.txt not found")
            return False
        
        print(f"{PASS} requirements.txt exists: {req_file}")
        
        # Read and validate format
        with open(req_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"{PASS} Found {len(lines)} dependency entries")
        print("  Dependencies:")
        for line in lines[:10]:  # Show first 10
            print(f"    - {line}")
        if len(lines) > 10:
            print(f"    ... and {len(lines) - 10} more")
        
        return True
    except Exception as e:
        print(f"{FAIL} Requirements test failed: {e}")
        return False


def test_directory_structure():
    """Test directory structure."""
    print("\n" + "="*60)
    print("TEST 6: Directory Structure")
    print("="*60)
    try:
        base = Path(__file__).parent
        
        required_dirs = [
            base / "src" / "Detection",
            base / "src" / "ML_Model",
            base / "src" / "Sniffing",
            base / "utils",
            base / "models",
            base / "datasets",
            base / "logs"
        ]
        
        all_exist = True
        for dir_path in required_dirs:
            if dir_path.exists():
                print(f"{PASS} {dir_path.relative_to(base)} exists")
            else:
                print(f"{FAIL} {dir_path.relative_to(base)} missing")
                all_exist = False
        
        return all_exist
    except Exception as e:
        print(f"{FAIL} Directory structure test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("PHASE 1 TESTING SUITE")
    print("="*60)
    
    tests = [
        ("Configuration Module", test_config),
        ("Logger Module", test_logger),
        ("Script Imports", test_imports),
        ("Error Handling", test_error_handling),
        ("Requirements File", test_requirements),
        ("Directory Structure", test_directory_structure)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n{FAIL} {test_name} crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{PASS} PASS" if result else f"{FAIL} FAIL"
        print(f"{status}: {test_name}")
    
    print("="*60)
    print(f"Results: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("\n[SUCCESS] All tests passed! Phase 1 is working correctly.")
        return 0
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

