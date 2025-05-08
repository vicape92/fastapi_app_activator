# main.py
import secrets # Para generar claves API seguras
from datetime import datetime # Importar datetime
from fastapi import FastAPI, APIRouter, HTTPException, Query, Depends, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

import database # Módulo para la base de datos
import security # Módulo para la seguridad y autenticación
from settings import settings # Para configuraciones generales

# --- Pydantic Models ---

class AppStatusResponse(BaseModel):
    app_name: str
    is_active: bool
    message: Optional[str] = None
    version_queried: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class ApplicationBase(BaseModel):
    name: str = Field(..., min_length=1, description="Nombre único de la aplicación")
    globally_active: bool = True
    min_version: Optional[str] = Field(None, pattern=r"^\d+\.\d+\.\d+$", description="Versión mínima (ej: '1.0.0')")
    allowed_users: Optional[List[str]] = Field(None, description="Lista de identificadores de usuario permitidos")
    valid_licenses: Optional[List[str]] = Field(None, description="Lista de claves de licencia válidas")
    message_active: str = "Application operational."
    message_inactive_default: str = "La aplicación está actualmente inactiva por razones no especificadas."
    message_inactive_global: str = "La aplicación está desactivada globalmente por el administrador."
    message_inactive_version: str = "Versión desactualizada. Por favor, actualice la aplicación."
    message_inactive_user: str = "Usuario no autorizado para esta aplicación."
    message_inactive_license: str = "Clave de licencia no válida, expirada o faltante."

class ApplicationCreate(ApplicationBase):
    pass

class ApplicationUpdate(BaseModel):
    globally_active: Optional[bool] = None
    min_version: Optional[str] = Field(None, pattern=r"^\d+\.\d+\.\d+$")
    allowed_users: Optional[List[str]] = None
    valid_licenses: Optional[List[str]] = None
    message_active: Optional[str] = None
    message_inactive_default: Optional[str] = None
    message_inactive_global: Optional[str] = None
    message_inactive_version: Optional[str] = None
    message_inactive_user: Optional[str] = None
    message_inactive_license: Optional[str] = None

class ApplicationResponse(ApplicationBase):
    id: int
    class Config:
        from_attributes = True

class ApplicationCreationResponse(ApplicationResponse):
    generated_api_key: str = Field(..., description="Clave API generada para esta aplicación. ¡Guárdala bien, no se mostrará de nuevo!")
    message: str = Field(..., description="Instrucciones o estado de la creación.")

# Nuevos modelos Pydantic para la gestión de API Keys
class ApiKeyBase(BaseModel):
    description: Optional[str] = Field(None, description="Descripción de la clave API")

class ApiKeyInfoResponse(ApiKeyBase):
    id: int
    application_id: int
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    # No incluir key_hash por seguridad

    class Config:
        from_attributes = True

class ApiKeyCreate(ApiKeyBase):
    description: str = Field("Clave API generada manualmente vía admin", description="Descripción para la nueva clave API")

class ApiKeyGeneratedResponse(BaseModel):
    plain_api_key: str = Field(..., description="La nueva clave API generada. ¡Guárdala bien, no se mostrará de nuevo!")
    id: int
    application_id: int
    description: str
    is_active: bool
    message: str

# --- FastAPI App Instance ---
app = FastAPI(
    title="API de Estado de Aplicaciones con Claves en BD",
    description="Gestiona y consulta el estado de activación de aplicaciones. Las claves de cliente se almacenan y validan contra la base de datos.",
    version="3.0.0",
)

# Router para los endpoints de administración, protegido con claves de admin del .env
admin_router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
    dependencies=[Depends(security.get_admin_api_key)],
    responses={404: {"description": "No encontrado"}}
)


# --- Evento de Arranque de la API ---
@app.on_event("startup")
def on_startup():
    """Crea las tablas de la BD al arrancar y puebla datos iniciales si es necesario."""
    database.create_db_and_tables()
    db = database.SessionLocal()
    try:
        database.populate_initial_data(db)
    finally:
        db.close()

# --- Funciones de Ayuda ---
def compare_versions(client_version_str: Optional[str], min_version_str: Optional[str]) -> bool:
    if not min_version_str: return True
    if not client_version_str: return False
    try:
        client_v_parts = list(map(int, client_version_str.split('.')))
        min_v_parts = list(map(int, min_version_str.split('.')))
        for i in range(max(len(client_v_parts), len(min_v_parts))):
            p_client = client_v_parts[i] if i < len(client_v_parts) else 0
            p_min = min_v_parts[i] if i < len(min_v_parts) else 0
            if p_client > p_min: return True
            if p_client < p_min: return False
        return True
    except ValueError: return False


# --- Endpoints de la API ---

@app.get(
    "/status_app",
    response_model=AppStatusResponse,
    tags=["Application Status"]
)
async def get_application_status(
    # La aplicación se identifica mediante la X-API-KEY.
    # db_app es el objeto ApplicationDB asociado a la clave API válida.
    db_app: database.ApplicationDB = Depends(security.get_application_from_api_key),
    app_version: Optional[str] = Query(None, description="Versión de la aplicación cliente (ej: '1.2.3')."),
    user_id: Optional[str] = Query(None, description="Identificador de usuario, si aplica."),
    license_key: Optional[str] = Query(None, description="Clave de licencia, si aplica.")
):
    """
    Verifica el estado de activación de una aplicación.
    La aplicación se identifica mediante la X-API-KEY proporcionada.
    """
    details = {
        "query_params_received": { # Para debug o información adicional
            "app_version": app_version,
            "user_id": user_id,
            "license_key": license_key,
        },
        "identified_app_id": db_app.id,
        "identified_app_name": db_app.name
    }

    is_active = True
    current_message = db_app.message_active

    # 1. Verificación de activación global
    if not db_app.globally_active:
        is_active = False
        current_message = db_app.message_inactive_global
    
    # 2. Verificación de versión (si aún se considera activa)
    if is_active and db_app.min_version:
        if not app_version: # Cliente debe enviar versión si min_version está configurada
            is_active = False
            current_message = f"{db_app.message_inactive_version} (El cliente no proporcionó versión, se requiere mínimo: {db_app.min_version})"
        elif not compare_versions(app_version, db_app.min_version):
            is_active = False
            current_message = f"{db_app.message_inactive_version} (Cliente: {app_version}, Mínimo: {db_app.min_version})"

    # 3. Verificación de usuario (si aún se considera activa y hay usuarios especificados)
    if is_active and db_app.allowed_users:
        if not user_id or user_id not in db_app.allowed_users:
            is_active = False
            current_message = db_app.message_inactive_user

    # 4. Verificación de licencia (si aún se considera activa y hay licencias especificadas)
    if is_active and db_app.valid_licenses:
        if not license_key or license_key not in db_app.valid_licenses:
            is_active = False
            current_message = db_app.message_inactive_license
    
    # Mensaje inactivo por defecto si ninguna condición específica estableció uno
    if not is_active and current_message == db_app.message_active: 
        current_message = db_app.message_inactive_default

    return AppStatusResponse(
        app_name=db_app.name, # Usamos el nombre de la app identificada por la clave
        is_active=is_active,
        message=current_message,
        version_queried=app_version,
        details=details
    )

# --- Endpoints de Administración (CRUD para Aplicaciones) ---

@admin_router.post(
    "/applications/",
    response_model=ApplicationCreationResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Admin - Applications"]
)
def create_application_and_key(
    app_data: ApplicationCreate,
    db: Session = Depends(database.get_db)
):
    """
    Crea una nueva configuración de aplicación y genera una clave API asociada
    que se guarda hasheada en la base de datos. La clave en texto plano se devuelve
    una única vez en esta respuesta.
    Requiere una API Key de Administrador válida.
    """
    db_app_existing = db.query(database.ApplicationDB).filter(database.ApplicationDB.name == app_data.name).first()
    if db_app_existing:
        raise HTTPException(status_code=400, detail=f"Aplicación con nombre '{app_data.name}' ya existe.")
    
    # 1. Crear la configuración de la aplicación
    new_app_config = database.ApplicationDB(**app_data.model_dump())
    db.add(new_app_config)
    db.commit()
    db.refresh(new_app_config) # Para obtener el ID asignado a new_app_config

    # 2. Generar y guardar la clave API para esta aplicación
    plain_api_key = secrets.token_urlsafe(32) # Genera clave segura en texto plano
    hashed_api_key = database.hash_api_key(plain_api_key) # Hashea la clave para guardarla

    new_db_api_key = database.ApiKeyDB(
        key_hash=hashed_api_key,
        application_id=new_app_config.id, # Asocia la clave con la aplicación recién creada
        description=f"Clave autogenerada para {new_app_config.name}"
    )
    db.add(new_db_api_key)
    db.commit()

    # Prepara la respuesta usando ApplicationResponse para los datos de la app
    # y luego añade los campos específicos de ApplicationCreationResponse.
    # Usamos model_validate para convertir el objeto SQLAlchemy a un modelo Pydantic
    app_response_data = ApplicationResponse.model_validate(new_app_config).model_dump()

    return ApplicationCreationResponse(
        **app_response_data, # Desempaqueta los campos de la app
        generated_api_key=plain_api_key, # Devuelve la clave en texto plano (¡solo esta vez!)
        message=f"Aplicación '{new_app_config.name}' creada con ID {new_app_config.id}. La clave API generada está activa y asociada. ¡Guárdala de forma segura, no se mostrará de nuevo!"
    )

@admin_router.get("/applications/", response_model=List[ApplicationResponse], tags=["Admin - Applications"])
def list_applications(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    apps = db.query(database.ApplicationDB).offset(skip).limit(limit).all()
    return apps

@admin_router.get("/applications/{app_name}", response_model=ApplicationResponse, tags=["Admin - Applications"])
def get_application_details(app_name: str, db: Session = Depends(database.get_db)):
    db_app = db.query(database.ApplicationDB).filter(database.ApplicationDB.name == app_name).first()
    if not db_app:
        raise HTTPException(status_code=404, detail=f"Aplicación '{app_name}' no encontrada.")
    return db_app

@admin_router.put("/applications/{app_name}", response_model=ApplicationResponse, tags=["Admin - Applications"])
def update_application(
    app_name: str,
    app_update_data: ApplicationUpdate,
    db: Session = Depends(database.get_db)
):
    db_app = db.query(database.ApplicationDB).filter(database.ApplicationDB.name == app_name).first()
    if not db_app:
        raise HTTPException(status_code=404, detail=f"Aplicación '{app_name}' no encontrada.")

    update_data = app_update_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_app, key, value)
    
    db.commit()
    db.refresh(db_app)
    return db_app

@admin_router.delete("/applications/{app_name}", status_code=status.HTTP_204_NO_CONTENT, tags=["Admin - Applications"])
def delete_application(app_name: str, db: Session = Depends(database.get_db)):
    db_app = db.query(database.ApplicationDB).filter(database.ApplicationDB.name == app_name).first()
    if not db_app:
        raise HTTPException(status_code=404, detail=f"Aplicación '{app_name}' no encontrada.")
    
    # Eliminar ApiKeyDB asociadas
    db.query(database.ApiKeyDB).filter(database.ApiKeyDB.application_id == db_app.id).delete(synchronize_session=False)
    
    db.delete(db_app)
    db.commit()
    return None

# --- Endpoints de Administración (CRUD para API Keys de una Aplicación) ---

@admin_router.get(
    "/applications/{app_name}/keys",
    response_model=List[ApiKeyInfoResponse],
    tags=["Admin - API Keys"],
    summary="Listar claves API de una aplicación"
)
def list_application_api_keys(app_name: str, db: Session = Depends(database.get_db)):
    """
    Lista todas las claves API (información básica, no la clave en sí) asociadas a una aplicación específica.
    """
    db_app = db.query(database.ApplicationDB).filter(database.ApplicationDB.name == app_name).first()
    if not db_app:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Aplicación '{app_name}' no encontrada.")
    
    api_keys = db.query(database.ApiKeyDB).filter(database.ApiKeyDB.application_id == db_app.id).all()
    if not api_keys:
        pass
    return api_keys

@admin_router.post(
    "/applications/{app_name}/keys",
    response_model=ApiKeyGeneratedResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Admin - API Keys"],
    summary="Generar nueva clave API para una aplicación"
)
def create_api_key_for_application(
    app_name: str,
    api_key_data: ApiKeyCreate, # Permite pasar una descripción
    db: Session = Depends(database.get_db)
):
    """
    Genera una nueva clave API para una aplicación existente.
    La clave en texto plano se devuelve una única vez.
    """
    db_app = db.query(database.ApplicationDB).filter(database.ApplicationDB.name == app_name).first()
    if not db_app:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Aplicación '{app_name}' no encontrada.")

    plain_api_key = secrets.token_urlsafe(32)
    hashed_api_key = database.hash_api_key(plain_api_key)

    new_db_api_key = database.ApiKeyDB(
        key_hash=hashed_api_key,
        application_id=db_app.id,
        description=api_key_data.description if api_key_data.description else f"Clave adicional para {db_app.name}",
        is_active=True # Nueva clave generada está activa por defecto
    )
    db.add(new_db_api_key)
    db.commit()
    db.refresh(new_db_api_key)

    return ApiKeyGeneratedResponse(
        plain_api_key=plain_api_key,
        id=new_db_api_key.id,
        application_id=new_db_api_key.application_id,
        description=new_db_api_key.description,
        is_active=new_db_api_key.is_active,
        message=f"Nueva clave API generada para la aplicación '{db_app.name}'. ¡Guárdala de forma segura!"
    )

@admin_router.put(
    "/api_keys/{key_id}/status",
    response_model=ApiKeyInfoResponse,
    tags=["Admin - API Keys"],
    summary="Activar o desactivar una clave API"
)
def update_api_key_status(
    key_id: int,
    activate: bool = Query(..., description="Establecer a 'true' para activar, 'false' para desactivar."),
    db: Session = Depends(database.get_db)
):
    """
    Activa o desactiva una clave API específica por su ID.
    """
    db_api_key = db.query(database.ApiKeyDB).filter(database.ApiKeyDB.id == key_id).first()
    if not db_api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Clave API con ID {key_id} no encontrada.")

    db_api_key.is_active = activate
    db_api_key.updated_at = datetime.utcnow() # Actualizar manualmente si onupdate no se dispara siempre
    db.commit()
    db.refresh(db_api_key)
    return db_api_key

@admin_router.delete(
    "/api_keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Admin - API Keys"],
    summary="Eliminar una clave API"
)
def delete_api_key(key_id: int, db: Session = Depends(database.get_db)):
    """
    Elimina permanentemente una clave API específica por su ID.
    Esta acción no se puede deshacer.
    """
    db_api_key = db.query(database.ApiKeyDB).filter(database.ApiKeyDB.id == key_id).first()
    if not db_api_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Clave API con ID {key_id} no encontrada.")

    db.delete(db_api_key)
    db.commit()
    return None

# Montar el router de administración en la aplicación principal
app.include_router(admin_router)


# --- Ejecución Principal (para desarrollo) ---
if __name__ == "__main__":
    import uvicorn
    print(f"Cargando configuraciones desde: {settings.model_config.get('env_file', 'variables de entorno')}")
    print(f"Claves ADMIN API (desde .env): {settings.ADMIN_API_KEYS}")
    print(f"URL de la Base de Datos: {settings.DATABASE_URL}")
    
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)