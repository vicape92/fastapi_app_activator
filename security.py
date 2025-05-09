# security.py
from fastapi import Security, HTTPException, status, Depends
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session

from settings import settings # Para las ADMIN_API_KEYS
# Importar modelos y helpers de la base de datos
from database import ApiKeyDB, ApplicationDB, get_db, hash_api_key

API_KEY_NAME = "X-API-KEY"
# auto_error=False para manejar la ausencia de la clave nosotros mismos si es necesario
api_key_header_auth = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_application_from_api_key(
    api_key_header: str = Security(api_key_header_auth),
    db: Session = Depends(get_db) # Inyectar sesión de BD
) -> ApplicationDB: # Devolverá el objeto ApplicationDB asociado
    """
    Valida la API key de cliente contra la base de datos 
    y devuelve la configuración de la aplicación asociada.
    """
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authenticated or API Key missing."
        )
    
    # Hashear la clave proporcionada por el cliente para compararla con los hashes almacenados
    hashed_provided_key = hash_api_key(api_key_header)
    
    # Buscar la clave hasheada en la base de datos
    db_api_key_entry = db.query(ApiKeyDB).filter(ApiKeyDB.key_hash == hashed_provided_key).first()
    
    # Verificar si la clave existe y está activa
    if not db_api_key_entry or not db_api_key_entry.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Clave API inválida o inactiva."
        )
    
    # Verificar si la clave está asociada a una aplicación (debería estarlo siempre)
    if not db_api_key_entry.application: 
        # Esto indicaría un problema de consistencia en los datos
        raise HTTPException(status_code=500, detail="Error de configuración de la Clave API: No hay aplicación asociada a esta clave.")

    # Devolver el objeto ApplicationDB asociado a la clave API válida
    return db_api_key_entry.application


async def get_admin_api_key(api_key_header: str = Security(api_key_header_auth)):
    """Valida la Admin API key contra las claves definidas en settings (desde .env)."""
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No autenticado o clave API de administrador faltante."
        )
    # Las claves de administrador siguen viniendo del .env por simplicidad y separación de roles
    if api_key_header in settings.ADMIN_API_KEYS:
        return api_key_header
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privilegios inválidos o insuficientes. Se requiere Clave API de Administrador."
        )