import os
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from searcher import run_search

app = FastAPI(title="LeakRadar API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@app.get("/api/search")
async def search(
    domain: str = Query(..., description="Target domain, e.g. example.com"),
    hibp_key: Optional[str] = Query(None),
    serp_key: Optional[str] = Query(None),
    github_token: Optional[str] = Query(None),
    gitlab_token: Optional[str] = Query(None),
    bd_key: Optional[str] = Query(None),
):
    if not domain or len(domain) < 3:
        raise HTTPException(400, "Invalid domain")
    try:
        result = await run_search(
            domain=domain,
            hibp_key=hibp_key or None,
            serp_key=serp_key or None,
            github_token=github_token or None,
            gitlab_token=gitlab_token or None,
            bd_key=bd_key or None,
        )
        return result
    except Exception as e:
        raise HTTPException(500, f"Search failed: {e}")


@app.get("/api/dorks")
async def dork_list(domain: str = Query(...)):
    from sources.dork_search import get_dork_queries
    return {"domain": domain, "queries": get_dork_queries(domain)}


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/{path:path}", include_in_schema=False)
async def static(path: str):
    fp = FRONTEND_DIR / path
    if fp.exists() and fp.is_file():
        return FileResponse(fp)
    return FileResponse(FRONTEND_DIR / "index.html")
