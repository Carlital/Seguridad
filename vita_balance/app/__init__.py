from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from database.config import Config
from sqlalchemy import event, text
from flask_login import current_user

# 1. Importaciones para Rate Limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

# 2. Instancia global del Limiter
#    - key_func: Identifica a los usuarios por su dirección IP.
#    - default_limits: Límites por defecto para TODAS las rutas de la aplicación.
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = app.config['SECRET_KEY']

    # Inicializar extensiones
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)  # 3. Inicializar el limiter con la app

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'

    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        print(f'✔ Cargando usuario con ID: {user_id}')
        return db.session.get(User, int(user_id))

    # ------------------------------
    # 🔐 BLOQUE NUEVO 1: Evento para setear app.user_id en la conexión activa
    # ------------------------------
    # Registramos el evento dentro del contexto de la app
    with app.app_context():
        from sqlalchemy import event

        @event.listens_for(db.engine, "before_cursor_execute")
        def set_app_userid(conn, cursor, statement, parameters, context, executemany):
            try:
                if current_user and not current_user.is_anonymous:
                    conn.exec_driver_sql("SET LOCAL app.user_id = %s", (current_user.id,))
            except Exception:
                pass
    # ------------------------------

    # 🔐 BLOQUE NUEVO 2: por compatibilidad, también mantenemos el before_request
    @app.before_request
    def set_pg_userid():
        """
        Marca la transacción actual con el id del usuario autenticado.
        Si current_user existe, ejecuta SET LOCAL en la sesión SQL actual.
        """
        try:
            if current_user and not current_user.is_anonymous:
                uid = str(current_user.id)
                #db.session.execute("SET LOCAL app.user_id = :uid", {"uid": uid})
                db.session.execute(text("SET LOCAL app.user_id = :uid"), {"uid": uid})
                app.logger.debug(f"✔ app.user_id establecido en PostgreSQL: {uid}")
            else:
                db.session.execute("SET LOCAL app.user_id = NULL")
        except Exception as e:
            app.logger.warning(f"⚠ No se pudo establecer app.user_id: {e}")
    # ------------------------------

    # Registro de blueprints
    from app.routes import home, auth, talleres, planes, dashboard, pages, chatbot, admin

    # 4. (Opcional pero recomendado) Aplicar un límite más estricto al blueprint de autenticación
    limiter.limit("10 per minute")(auth.bp)

    app.register_blueprint(home.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(talleres.bp)
    app.register_blueprint(planes.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(pages.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(chatbot.bp)

    return app