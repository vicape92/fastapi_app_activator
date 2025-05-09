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

    # Credenciales para el primer usuario del panel de administración (SQLAdmin)
    # Estos solo se usarán si no hay ningún AdminUser en la base de datos.
    # ¡Cambia estos valores en tu .env!
    DEFAULT_ADMIN_PANEL_USERNAME: str = "admin"
    DEFAULT_ADMIN_PANEL_PASSWORD: str = "changeme"
    ADMIN_PANEL_SECRET_KEY: str = "please_change_me_in_dot_env" # Nueva clave para sesiones del panel admin

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding='utf-8',
        extra='ignore'
    )

settings = Settings()