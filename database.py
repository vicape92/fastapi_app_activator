# database.py
from sqlalchemy import create_engine, Column, Integer, String, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timezone
import hashlib
import secrets
from passlib.context import CryptContext

from settings import settings

DATABASE_URL = settings.DATABASE_URL
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configuración de Passlib para hasheo de contraseñas
crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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

# Nuevo modelo para usuarios del panel de administración
class AdminUserDB(Base):
    __tablename__ = "admin_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    # Podrías añadir más campos como: is_active, last_login, email, etc.

    def verify_password(self, plain_password: str) -> bool:
        return crypt_context.verify(plain_password, self.password_hash)

    def set_password(self, plain_password: str):
        self.password_hash = crypt_context.hash(plain_password)

def create_db_and_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def populate_initial_data(db: Session):
    # Primero, poblar aplicaciones y claves API como antes
    if db.query(ApplicationDB).count() == 0:
        print("INFO: No ApplicationDB entries found. Populating initial app configs and API keys...")
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
        # print("La base de datos ya contiene datos. Omitiendo población inicial.")
        pass

    # Segundo, crear el usuario administrador por defecto si no existe ninguno
    if db.query(AdminUserDB).count() == 0:
        print(f"INFO: No AdminUserDB users found. Attempting to create default admin user.")
        print(f"INFO: Using DEFAULT_ADMIN_PANEL_USERNAME: '{settings.DEFAULT_ADMIN_PANEL_USERNAME}' for default admin.")
        # Asegúrate de que DEFAULT_ADMIN_PANEL_PASSWORD también se está leyendo como esperas.
        # No imprimimos la contraseña directamente por seguridad.
        if not settings.DEFAULT_ADMIN_PANEL_USERNAME or not settings.DEFAULT_ADMIN_PANEL_PASSWORD:
            print("ERROR: DEFAULT_ADMIN_PANEL_USERNAME or DEFAULT_ADMIN_PANEL_PASSWORD is not set in settings.")
            return

        default_admin = AdminUserDB(username=settings.DEFAULT_ADMIN_PANEL_USERNAME)
        default_admin.set_password(settings.DEFAULT_ADMIN_PANEL_PASSWORD) # Hashear la contraseña
        db.add(default_admin)
        db.commit()
        print(f"INFO: Default admin user '{settings.DEFAULT_ADMIN_PANEL_USERNAME}' created successfully.")
    else:
        print("INFO: AdminUserDB already contains users. Skipping creation of default admin user.")