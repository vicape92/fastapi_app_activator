# database.py
from sqlalchemy import create_engine, Column, Integer, String, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timezone
import hashlib
import secrets # <--- AÑADIR IMPORT SECRETS

from settings import settings

DATABASE_URL = settings.DATABASE_URL
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()

class ApplicationDB(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    globally_active = Column(Boolean, default=True)
    min_version = Column(String, nullable=True)
    allowed_users = Column(JSON, nullable=True)
    valid_licenses = Column(JSON, nullable=True)
    message_active = Column(String, default="Aplicación operativa.")
    message_inactive_default = Column(String, default="La aplicación está inactiva actualmente por razones no especificadas.")
    message_inactive_global = Column(String, default="La aplicación está deshabilitada globalmente por el administrador.")
    message_inactive_version = Column(String, default="Versión desactualizada. Por favor, actualice la aplicación.")
    message_inactive_user = Column(String, default="Usuario no autorizado para esta aplicación.")
    message_inactive_license = Column(String, default="Clave de licencia inválida, expirada o faltante.")
    api_keys = relationship("ApiKeyDB", back_populates="application", cascade="all, delete-orphan")

class ApiKeyDB(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    application = relationship("ApplicationDB", back_populates="api_keys")

def create_db_and_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def populate_initial_data(db: Session):
    if db.query(ApplicationDB).count() == 0:
        print("Poblando configuraciones iniciales de aplicaciones y claves API...")
        initial_apps_configs = []

        generated_keys_info = []

        for app_config_data in initial_apps_configs:
            # 1. Crear la configuración de la aplicación
            app_config = ApplicationDB(**app_config_data)
            db.add(app_config)
            db.flush() # Para obtener el app_config.id antes del commit final

            # 2. Generar y guardar la clave API para esta aplicación
            plain_api_key = secrets.token_urlsafe(32)
            hashed_api_key = hash_api_key(plain_api_key)

            new_db_api_key = ApiKeyDB(
                key_hash=hashed_api_key,
                application_id=app_config.id, # Asocia con la app recién creada
                description=f"Clave inicial autogenerada para {app_config.name}"
            )
            db.add(new_db_api_key)
            
            generated_keys_info.append({
                "app_name": app_config.name,
                "api_key": plain_api_key # Guardamos la clave en texto plano para mostrarla
            })
        
        db.commit() # Commit de todas las apps y claves
        print("Datos iniciales poblados exitosamente.")
        print("--------------------------------------------------------------------")
        print("CLAVES API GENERADAS PARA APLICACIONES INICIALES (¡GUARDAR DE FORMA SEGURA!):")
        for key_info in generated_keys_info:
            print(f"  App: {key_info['app_name']:<25} Clave API: {key_info['api_key']}")
        print("--------------------------------------------------------------------")

    else:
        # Esto es normal si la base de datos ya existe y tiene datos.
        # print("La base de datos ya contiene datos. Omitiendo población inicial.")
        pass