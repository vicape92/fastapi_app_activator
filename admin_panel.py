# admin_panel.py
from fastapi import FastAPI, HTTPException
from sqlalchemy.orm import Session
from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.authentication import AuthCredentials, BaseUser

from database import engine, ApplicationDB, ApiKeyDB, AdminUserDB, get_db, SessionLocal # Added SessionLocal
from settings import settings

# Nueva clase BaseUser para representar un administrador autenticado
class AuthenticatedAdmin(BaseUser):
    def __init__(self, user_id: int, username: str) -> None:
        self.user_id = user_id
        self.username = username

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.username

class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool | RedirectResponse:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        
        print(f"DEBUG_LOGIN: Intentando inicio de sesión para el usuario: '{username}'")

        if not username or not password:
            print("DEBUG_LOGIN: Nombre de usuario o contraseña no proporcionados en el formulario.")
            return False 

        db: Session = next(get_db())
        admin_user = None
        try:
            admin_user = db.query(AdminUserDB).filter(AdminUserDB.username == username).first()

            if not admin_user:
                print(f"DEBUG_LOGIN: Usuario '{username}' no encontrado en la base de datos.")
                return False
            
            if not admin_user.verify_password(password):
                print(f"DEBUG_LOGIN: Verificación de contraseña fallida para el usuario '{username}'.")
                return False
            
            print(f"DEBUG_LOGIN: Verificación de contraseña exitosa para el usuario '{username}'.")
            request.session.update({"admin_user_id": admin_user.id, "admin_user_name": admin_user.username})
            print(f"DEBUG_LOGIN: Sesión actualizada para el usuario '{username}'. Inicio de sesión exitoso.")
            
            redirect_url_name = "admin:applicationdb_list"
            try:
                redirect_url = request.url_for(redirect_url_name) 
                print(f"DEBUG_LOGIN: Redirigiendo explícitamente a '{redirect_url_name}': {redirect_url}")
                return RedirectResponse(url=redirect_url, status_code=302)
            except Exception as e:
                print(f"DEBUG_LOGIN: Error generando URL para '{redirect_url_name}': {e}. Redirigiendo a admin:index.")
                redirect_url = request.url_for("admin:index") 
                print(f"DEBUG_LOGIN: Redirigiendo explícitamente a admin:index: {redirect_url}")
                return RedirectResponse(url=redirect_url, status_code=302)

        except Exception as e:
            print(f"DEBUG_LOGIN: Ocurrió una excepción durante el inicio de sesión: {e}")
            return False
        finally:
            if db:
                db.close()

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        print("DEBUG_AUTH: Usuario desconectado, sesión borrada.")
        return True

    async def authenticate(self, request: Request) -> tuple[AuthCredentials, BaseUser] | RedirectResponse | None:
        print(f"DEBUG_AUTH: Autenticación llamada para la ruta: {request.url.path}")
        print(f"DEBUG_AUTH: Contenido de la sesión antes de la comprobación de autenticación: {request.session}")
        
        admin_user_id = request.session.get("admin_user_id")
        admin_user_name = request.session.get("admin_user_name")

        if not admin_user_id or not admin_user_name:
            print(f"DEBUG_AUTH: admin_user_id o admin_user_name no están en la sesión para la ruta: {request.url.path}")
            if "login" not in request.url.path and "static" not in request.url.path : # Permitir acceso a archivos estáticos para la página de login
                login_url = request.url_for("admin:login")
                print(f"DEBUG_AUTH: Redirigiendo a login_url: {login_url}")
                return RedirectResponse(login_url, status_code=302)
            else:
                print(f"DEBUG_AUTH: Sin sesión, pero en ruta de login/static o no se necesita redirección. Ruta: {request.url.path}")
                return None
        
        print(f"DEBUG_AUTH: Sesión válida para user_id '{admin_user_id}', username '{admin_user_name}'. Devolviendo AuthenticatedAdmin.")
        return AuthCredentials(["authenticated"]), AuthenticatedAdmin(user_id=admin_user_id, username=admin_user_name)

class ApplicationAdmin(ModelView, model=ApplicationDB):
    identity = "applicationdb"
    column_list = [ApplicationDB.id, ApplicationDB.name, ApplicationDB.globally_active, ApplicationDB.min_version]
    column_searchable_list = [ApplicationDB.name]
    column_sortable_list = [ApplicationDB.id, ApplicationDB.name]
    form_excluded_columns = [ApplicationDB.api_keys]
    name = "Aplicación"
    name_plural = "Aplicaciones"
    icon = "fa-solid fa-rocket"

class ApiKeyAdmin(ModelView, model=ApiKeyDB):
    identity = "apikeydb"
    column_list = [ApiKeyDB.id, ApiKeyDB.application_id, "application.name", ApiKeyDB.description, ApiKeyDB.is_active, ApiKeyDB.created_at]
    column_labels = {ApiKeyDB.application_id: "ID App", "application.name": "Nombre App", ApiKeyDB.description: "Descripción", ApiKeyDB.is_active: "Activa"}
    column_searchable_list = [ApiKeyDB.description, "application.name"]
    column_sortable_list = [ApiKeyDB.id, ApiKeyDB.application_id, ApiKeyDB.created_at, ApiKeyDB.is_active]
    form_columns = [ApiKeyDB.application, ApiKeyDB.description, ApiKeyDB.is_active]
    can_create = False
    can_edit = True
    can_delete = True
    name = "Clave API"
    name_plural = "Claves API"
    icon = "fa-solid fa-key"

class AdminUserAdmin(ModelView, model=AdminUserDB):
    identity = "adminuserdb"
    column_list = [AdminUserDB.id, AdminUserDB.username]
    column_searchable_list = [AdminUserDB.username]
    column_sortable_list = [AdminUserDB.id, AdminUserDB.username]
    
    form_excluded_columns = [AdminUserDB.password_hash]
    column_details_exclude_list = [AdminUserDB.password_hash]

    name = "Usuario Admin"
    name_plural = "Usuarios Admin"
    icon = "fa-solid fa-user-shield"

    async def on_model_change(self, data: dict, model: AdminUserDB, is_created: bool, request: Request) -> None:
        # Password hashing is handled by the model's set_password method,
        # but SQLAdmin might try to set it directly.
        # This ensures if 'password' field is in form, it's hashed.
        # However, for AdminUser, we typically handle password changes via a custom form or method.
        # For now, we assume password changes are not directly done via a simple 'password' field in the main form.
        # If you add a password field to the form, you'd handle its hashing here.
        pass

    async def on_model_delete(self, model: AdminUserDB, request: Request) -> None:
        # Usar SessionLocal directamente ya que self.session_maker podría no estar disponible
        # o correctamente configurado en todos los contextos de ModelView.
        db = SessionLocal()
        try:
            count = db.query(AdminUserDB).count()
            if count <= 1:
                raise HTTPException(status_code=400, detail="No se puede eliminar el último usuario administrador.")
        finally:
            db.close()

def init_admin(app: FastAPI, engine_instance):
    authentication_backend = AdminAuth(secret_key=settings.ADMIN_PANEL_SECRET_KEY)
    
    admin_panel = Admin(
        app=app, 
        engine=engine_instance, 
        title="Panel de Administración", 
        base_url="/admin-panel",
        authentication_backend=authentication_backend
    )

    admin_panel.add_view(ApplicationAdmin)
    admin_panel.add_view(ApiKeyAdmin)
    admin_panel.add_view(AdminUserAdmin)
    # No need to return admin_panel, as it attaches to the app
