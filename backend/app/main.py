from fastapi import FastAPI, HTTPException

from . import routes

app = FastAPI()

# Register routers
app.include_router(routes.agent_router)
app.include_router(routes.internal_router)

