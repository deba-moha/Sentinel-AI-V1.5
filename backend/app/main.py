"""
Sentinel AI - V1.0 Foundation Entrypoint
FastAPI server initializing SQLite database, CORS, and API routers.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.app.core.config import settings
from backend.app.core.logging_config import logger
from backend.app.database.session import init_db
from backend.app.api import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle event handler: initializes database on startup."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]")
    try:
        init_db()
        logger.info("Database schema verified and tables initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
        raise e
    yield
    logger.info(f"Shutting down {settings.PROJECT_NAME}")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Sentinel AI - Agentic AI-powered cybersecurity monitoring & threat investigation platform (V1.0 Foundation)",
    lifespan=lifespan
)

# CORS Middleware
origins = settings.CORS_ORIGINS
if isinstance(origins, str):
    origins = [origins]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred in Sentinel AI backend."}
    )

# Include API Router
app.include_router(api_router)


@app.get("/", tags=["General"])
def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "docs_url": "/docs"
    }


@app.get("/health", tags=["General"])
def health_check():
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "database": "connected"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=True)

