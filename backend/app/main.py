"""
AgentGuard — FastAPI Application Entry Point

This is the minimal stub for Milestone 1.
Security routes, WebSocket endpoints, and agent endpoints
will be added in Milestones 2-16.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Context-Aware Runtime Security for Autonomous AI Agents",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow local dashboard dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
def health_check():
    """Basic health check — used by dashboard and deployment monitors."""
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "llm_enabled": settings.llm_provider is not None,
    }


@app.get("/", tags=["System"])
def root():
    return {"message": f"{settings.app_name} is running. Visit /docs for API documentation."}
