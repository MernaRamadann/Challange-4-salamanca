#!/usr/bin/env python
"""
Run script for Autonomous Forensic Orchestrator
Start this to launch the web interface
"""
import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.resolve()
sys.path.insert(0, str(project_root))

if __name__ == "__main__":
    import uvicorn

    print("\n" + "=" * 60)
    print("  Autonomous Forensic Orchestrator")
    print("=" * 60)
    print(f"\n  Starting server...")
    print(f"\n  Open in browser: http://localhost:8000")
    print(f"  API Documentation: http://localhost:8000/docs")
    print("\n" + "=" * 60 + "\n")

    # Change to project directory
    os.chdir(project_root)

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
