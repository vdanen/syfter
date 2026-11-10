"""
Main API router combining all route modules.
"""

from fastapi import APIRouter

from . import products, systems, scans, queries, exports, layers, relationships, vulcan, tags

api_router = APIRouter()

api_router.include_router(products.router, prefix="/products", tags=["products"])
api_router.include_router(systems.router, prefix="/systems", tags=["systems"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(queries.router, prefix="/query", tags=["queries"])
api_router.include_router(exports.router, prefix="/export", tags=["exports"])
api_router.include_router(layers.router, prefix="/layers", tags=["layers"])
api_router.include_router(relationships.router, prefix="/relationships", tags=["relationships"])
api_router.include_router(vulcan.router, prefix="/vulcan", tags=["vulcan"])
api_router.include_router(tags.router, prefix="/tags", tags=["tags"])