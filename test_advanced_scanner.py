#!/usr/bin/env python3
"""
Test script for the advanced scanner functionality
"""

import asyncio
import json
import sys
import os

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from advanced_scanner import AdvancedWebScanner

async def test_advanced_scanner():
    """Test the advanced scanner"""
    print("Testing Advanced Web Scanner...")
    
    # Test with a safe target
    scanner = AdvancedWebScanner("https://httpbin.org", max_workers=5)
    
    try:
        print("Running comprehensive scan...")
        results = await scanner.run_comprehensive_scan()
        
        print(f"Scan completed! Found {len(results)} test results.")
        
        # Display results
        for test_name, result in results.items():
            print(f"\n{test_name}:")
            if isinstance(result, dict):
                print(json.dumps(result, indent=2))
            else:
                print(f"  {result}")
                
    except Exception as e:
        print(f"Error during scan: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_advanced_scanner())