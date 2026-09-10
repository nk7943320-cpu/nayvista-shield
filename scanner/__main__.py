"""
SentinelScan - Module Entrypoint
Enables invocation via: python -m scanner ...
"""

import sys
import os

# Ensure package is on sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from scanner.cli import main

if __name__ == "__main__":
    main()
