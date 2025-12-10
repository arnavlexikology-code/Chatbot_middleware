from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    INTERNAL_SHARED_SECRET: str = Field(..., env="INTERNAL_SHARED_SECRET")
    MIDDLEWARE_BASE_URL: str = Field(..., env="MIDDLEWARE_BASE_URL")
    COPILOTSTUDIOAGENT__ENVIRONMENTID: str | None = Field(None)

    class Config:
        env_file = ".env"


settings = Settings()


