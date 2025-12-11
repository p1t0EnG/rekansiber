# app/ransom_info/routes.py
from fastapi import APIRouter, Query, HTTPException
from typing import Any

router = APIRouter()

@router.get("/summary")
async def ransom_summary(victim: str = Query(..., min_length=2, max_length=255)):
    """
    Placeholder route for ransom info. Implementation will call ransom APIs (e.g., RansomHub)
    """
    # For now, return a simple placeholder
    return {"victim": victim, "note": "ransom info feature coming soon"}
