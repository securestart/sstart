#!/usr/bin/env python3
"""
Simple Python script to demonstrate sstart usage.
This script prints all environment variables to show how sstart injects secrets.
"""

import os
import sys

def main():
    print("=" * 60)
    print("All Environment Variables")
    print("=" * 60)
    print()
    
    # Print all environment variables sorted by name
    for key, value in sorted(os.environ.items()):
        print(f"{key}={value}")
    
    print()
    print("=" * 60)
    print(f"Total: {len(os.environ)} environment variables")
    print("=" * 60)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
