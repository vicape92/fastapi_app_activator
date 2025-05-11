# settings.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Set
from pydantic import Field

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./app_status.db"
    # Las claves API de cliente ahora se gestionan en la BD.
    # API_KEYS ya no se usa para claves de cliente, pero puedes mantenerlo si tienes otros usos.
    # Las ADMIN_API_KEYS siguen viniendo del .env para la gestión de la API.
    ADMIN_API_KEYS: Set[str] = Field(default_factory=set) # Para proteger endpoints de admin

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding='utf-8',
        extra='ignore'
    )

settings = Settings()