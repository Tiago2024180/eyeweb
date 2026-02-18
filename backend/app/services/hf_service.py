"""
===========================================
Eye Web Backend — Hugging Face AI Service
===========================================

Handles:
1. AI Classification of news articles using HF Inference API (bart-large-mnli)
2. Dataset auto-write to HF Hub (search_history.jsonl)

Ported from the test-site Node.js implementation.
"""

import logging
import asyncio
import json
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ===========================================
# CONSTANTS
# ===========================================

HF_MODEL = "facebook/bart-large-mnli"

HF_CLASSIFICATION_LABELS = [
    "cybersecurity data breach",
    "hacking or cyber attack",
    "ransomware or malware attack",
    "phishing or social engineering",
    "security vulnerability or exploit",
    "unrelated to cybersecurity",
]

SEC_LABELS = [l for l in HF_CLASSIFICATION_LABELS if l != "unrelated to cybersecurity"]


# ===========================================
# AI CLASSIFICATION
# ===========================================

async def classify_text(text: str, hf_token: str) -> Optional[dict]:
    """
    Classify a single text using HF Inference API (zero-shot).
    Returns { topLabel, topScore, securityScore, isSecurityRelated } or None.
    """
    if not hf_token or not text:
        return None

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(
                f"https://router.huggingface.co/hf-inference/models/{HF_MODEL}",
                headers={
                    "Authorization": f"Bearer {hf_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "inputs": text[:512],
                    "parameters": {"candidate_labels": HF_CLASSIFICATION_LABELS},
                },
            )

        if resp.status_code != 200:
            # Model might be loading (503)
            return None

        data = resp.json()

        # Handle both response formats:
        # Old format: {"labels": [...], "scores": [...]}
        # New router format: [{"label": "...", "score": 0.83}, ...]
        if isinstance(data, list):
            # New router format — array of {label, score} objects
            if not data or "label" not in data[0]:
                return None
            labels = [item["label"] for item in data]
            scores = [item["score"] for item in data]
        elif isinstance(data, dict) and isinstance(data.get("labels"), list):
            # Old format
            labels = data["labels"]
            scores = data["scores"]
        else:
            return None

        # Aggregate security relevance score
        security_score = 0.0
        for label in SEC_LABELS:
            idx = labels.index(label) if label in labels else -1
            if idx >= 0:
                security_score += scores[idx]

        top_label = labels[0]
        top_score = scores[0]

        return {
            "topLabel": top_label,
            "topScore": round(top_score * 100),
            "securityScore": round(security_score * 100),
            "isSecurityRelated": (
                top_label != "unrelated to cybersecurity"
                and security_score > 0.45
            ),
        }
    except Exception as e:
        logger.debug(f"HF classification error: {e}")
        return None


async def classify_articles(articles: list[dict], hf_token: str) -> list[dict]:
    """
    Classify the top N articles in parallel, attach aiClassification field,
    and sort by security score descending.
    """
    if not hf_token or len(articles) == 0:
        return articles

    max_classify = min(len(articles), 10)
    to_classify = articles[:max_classify]

    tasks = [classify_text(a.get("title", ""), hf_token) for a in to_classify]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        if not isinstance(result, Exception) and result is not None:
            to_classify[i]["aiClassification"] = result

    # Sort: AI-classified security articles first (by score), then unclassified
    articles.sort(
        key=lambda a: a.get("aiClassification", {}).get("securityScore", -1),
        reverse=True,
    )

    return articles


# ===========================================
# HF DATASET WRITE
# ===========================================

async def push_to_hf_dataset(
    file_path: str,
    content: str,
    hf_token: str,
    repo: str,
    commit_message: str = "",
) -> bool:
    """Upload a file to a HF dataset repo using the API."""
    if not hf_token:
        return False

    try:
        url = f"https://huggingface.co/api/datasets/{repo}/upload/main/{file_path}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {hf_token}"},
                files={"file": (file_path.split("/")[-1], content.encode("utf-8"))},
                data={"commit_message": commit_message or f"Auto-update: {file_path}"},
            )
        if resp.status_code in (200, 201):
            logger.info(f"[HF] Pushed {file_path} to {repo}")
            return True
        else:
            logger.warning(f"[HF] Push failed ({resp.status_code}): {resp.text[:200]}")
            return False
    except Exception as e:
        logger.warning(f"[HF] Push error for {file_path}: {e}")
        return False


async def write_breach_to_dataset(
    domain: str,
    breaches: list[dict],
    hf_token: str,
    repo: str,
):
    """
    Write breach data to HF dataset:
    1. Individual domain file in .autochecks/
    2. Update search_history.jsonl (visible to Dataset Viewer)
    """
    if not hf_token:
        return

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # 1. Individual domain file
    record = {
        "domain": domain,
        "checkedAt": timestamp,
        "breachCount": len(breaches),
        "breaches": breaches,
    }
    file_path = f".autochecks/{domain}.json"
    content = json.dumps(record, indent=2)
    ok = await push_to_hf_dataset(
        file_path, content, hf_token, repo,
        f"Auto: breach data for {domain}",
    )

    # 2. Update search_history.jsonl
    if ok:
        await _update_search_index(domain, timestamp, breaches, hf_token, repo)


async def _update_search_index(
    domain: str,
    timestamp: str,
    breaches: list[dict],
    hf_token: str,
    repo: str,
):
    """Maintain search_history.jsonl for HF Dataset Viewer."""
    try:
        # Read existing
        existing: list[dict] = []
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://huggingface.co/datasets/{repo}/resolve/main/search_history.jsonl?t={int(time.time())}",
            )
            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            existing.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

        # Add new rows (flat format for Dataset Viewer)
        for b in breaches:
            existing.append({
                "domain": domain,
                "checkedAt": timestamp,
                "breachName": b.get("Name") or b.get("name", ""),
                "breachTitle": b.get("Title") or b.get("title", ""),
                "breachDate": b.get("BreachDate") or b.get("breachDate") or b.get("breach_date", ""),
                "pwnCount": b.get("PwnCount") or b.get("pwnCount") or b.get("pwn_count", 0),
                "dataClasses": ", ".join(b.get("DataClasses") or b.get("dataClasses") or b.get("data_classes") or []),
                "description": (b.get("Description") or b.get("description") or "")[:300],
            })

        # Write as JSONL
        jsonl = "\n".join(json.dumps(r, ensure_ascii=False) for r in existing) + "\n"
        await push_to_hf_dataset(
            "search_history.jsonl",
            jsonl,
            hf_token,
            repo,
            f"Update search history (+1 domain: {domain})",
        )
        logger.info(f"[HF] Updated search_history.jsonl ({len(existing)} total rows)")

    except Exception as e:
        logger.warning(f"[HF] Failed to update search index: {e}")


async def read_hf_dataset_breaches(domain: str, hf_token: str, repo: str) -> dict:
    """Read breach data for a domain from the HF dataset."""
    from .news_service import get_root_domain

    root_domain = get_root_domain(domain)
    brand = root_domain.split(".")[0]

    possible_paths = [
        f".autochecks/{root_domain}.json",
        f".autochecks/{brand}.json",
        f"breaches/{root_domain}.json",
        f"breaches/{brand}.json",
        f"datasets/breaches-{root_domain}.json",
    ]

    async with httpx.AsyncClient(timeout=8.0) as client:
        for file_path in possible_paths:
            try:
                url = f"https://huggingface.co/datasets/{repo}/resolve/main/{file_path}?t={int(time.time())}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    return {"found": True, "path": file_path, "data": data}
            except Exception:
                continue

    return {"found": False}
