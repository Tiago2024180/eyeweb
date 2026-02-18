"""
===========================================
Eye Web Backend — News & HF Dataset Router
===========================================

Endpoints:
- GET  /news/search/{query}   — Search cybersecurity news (Google News, Bing, GDELT, 12 RSS)
- GET  /news/hf-breaches/{domain} — Read breach data from HF dataset
- GET  /news/dataset-explorer  — Fetch search_history.jsonl for Dataset Explorer

Ported from the test-site Node.js implementation.
"""

import logging
from fastapi import APIRouter, Query

from ..config import get_settings
from ..services.news_service import search_news
from ..services.hf_service import (
    classify_articles,
    read_hf_dataset_breaches,
)

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(
    prefix="/news",
    tags=["News & AI"],
    responses={404: {"description": "Not found"}},
)


@router.get(
    "/search/{query}",
    summary="Search cybersecurity news",
    description="Searches Google News, Bing News, GDELT, and 12 security RSS feeds "
                "for breach/hack/vulnerability reports. Optionally classifies articles "
                "with HF AI (bart-large-mnli).",
)
async def news_search(
    query: str,
    type: str = Query("domain", description="Query type: email, domain, or url"),
):
    """
    Search for unverified cybersecurity news reports across multiple sources.
    Results include AI classification when HF token is configured.
    """
    hf_token = settings.HF_TOKEN

    # Search all news sources
    payload = await search_news(query, type, hf_token=hf_token)

    # AI classification via HF Inference API
    if hf_token and payload.get("results"):
        try:
            payload["results"] = await classify_articles(payload["results"], hf_token)
        except Exception as e:
            logger.warning(f"AI classification failed: {e}")

    return payload


@router.get(
    "/hf-breaches/{domain}",
    summary="Read breach data from HF dataset",
    description="Reads stored breach data for a domain from the HF dataset repo.",
)
async def hf_breaches(domain: str):
    """Read breach data from HF dataset for a given domain."""
    hf_token = settings.HF_TOKEN
    repo = settings.HF_DATASET_REPO

    result = await read_hf_dataset_breaches(domain, hf_token, repo)
    return {
        "domain": domain,
        "datasetRepo": repo,
        **result,
    }


@router.get(
    "/dataset-explorer",
    summary="Dataset Explorer data",
    description="Returns the search_history.jsonl rows for the frontend Dataset Explorer table.",
)
async def dataset_explorer():
    """Fetch the search_history.jsonl from HF for the Dataset Explorer UI."""
    import httpx
    import json
    import time

    repo = settings.HF_DATASET_REPO
    url = f"https://huggingface.co/datasets/{repo}/resolve/main/search_history.jsonl?t={int(time.time())}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {"rows": [], "total": 0, "repo": repo}

            rows = []
            for line in resp.text.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

            return {"rows": rows, "total": len(rows), "repo": repo}
    except Exception as e:
        logger.warning(f"Dataset Explorer fetch error: {e}")
        return {"rows": [], "total": 0, "repo": repo, "error": str(e)}
