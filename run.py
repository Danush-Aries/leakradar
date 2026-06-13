#!/usr/bin/env python3
import uvicorn
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

if __name__ == "__main__":
    print("\n  LeakRadar — Domain Breach Intelligence")
    print("  Open: http://localhost:8765\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8765, reload=True, app_dir="backend")
