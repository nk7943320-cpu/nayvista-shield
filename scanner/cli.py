"""
NayVista Shield - Terminal CLI Entrypoint
Forwards execution to the modular scanner.cli package while preserving backward compatibility.
"""

import sys
import os

# Ensure package is on sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from scanner.cli.router import main, parse_arguments

if __name__ == "__main__":
    main()
