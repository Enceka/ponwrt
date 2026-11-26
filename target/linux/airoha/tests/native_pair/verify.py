#!/usr/bin/env python3
"""Exercise ABI3 pair admission and serialized policy authorization."""
from pathlib import Path
import subprocess
import sys
r = Path(__file__).resolve().parent
for script in ('verify_source3.py', 'verify_policy_core.py'):
    subprocess.run([sys.executable, str(r / script)], check=True)
