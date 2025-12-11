# app/ioc_service/routes.py
from fastapi import APIRouter, Query, HTTPException
from typing import Any
from .provider import aggregate_ioc

router = APIRouter()

@router.get("/check")
async def check_ioc(ioc: str = Query(..., min_length=2, max_length=255)):
    """
    Check a single IOC (ip/domain/hash). Example: /ioc/check?ioc=8.8.8.8
    """
    try:
        result = await aggregate_ioc(ioc)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # In production, log exception to Sentry instead of exposing raw error
        raise HTTPException(status_code=500, detail="Internal error")
