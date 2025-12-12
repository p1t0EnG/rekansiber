# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .extensions import init_extensions
from .ioc_service.routes import router as ioc_router
from .ransom_info.routes import router as ransom_router

def create_app() -> FastAPI:
    app = FastAPI(title="RA Security API")

    # Init extensions (cache, etc)
    init_extensions()

    # CORS - tighten this in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOW_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(ioc_router, prefix="/ioc", tags=["ioc"])
    app.include_router(ransom_router, prefix="/ransom", tags=["ransom"])

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app

app = create_app()
