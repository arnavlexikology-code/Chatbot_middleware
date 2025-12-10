from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    BACKEND_SHARED_SECRET: str = Field(..., env="BACKEND_SHARED_SECRET")
    COPILOTSTUDIOAGENT__ENVIRONMENTID: str | None = Field(None)
    MIDDLEWARE_BASE_URL: str = Field(..., env="MIDDLEWARE_BASE_URL")
    INTERNAL_SHARED_SECRET: str = Field(..., env="INTERNAL_SHARED_SECRET")

    class Config:
        env_file = ".env"


settings = Settings()


