import os

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard_to_guess_string'
    FLASK_APP = os.environ.get('FLASK_APP')
    
    # Security Config
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_NAME = 'biblioteca_session'
    
    # Database Config
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configuración del Pool de Conexiones (Optimización)
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,        # Mantener 10 conexiones abiertas
        'max_overflow': 20,     # Permitir 20 extra si hay pico de carga
        'pool_recycle': 1800,   # Reciclar conexiones cada 30 min para evitar timeouts
        'pool_pre_ping': True,  # Verificar conexión antes de usarla (evita errores de "server closed connection")
        # 'options': '-c search_path=usuario,biblioteca,auditoria' # Forzar search_path si no está en el rol
    }
    
    # Future JWT Config (Placeholder)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt_secret_key_change_this'
    
    # Data Encryption Key (Fernet)
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

    # Rate Limiting Config
    # Capacidad del bucket (ráfaga máxima)
    RATELIMIT_CAPACITY = int(os.environ.get('RATELIMIT_CAPACITY', 10))
    # Tasa de recarga (tokens por segundo)
    RATELIMIT_REFILL_RATE = float(os.environ.get('RATELIMIT_REFILL_RATE', 1.0))

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    WTF_CSRF_ENABLED = False
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    SECRET_KEY = 'test_secret_key'
    JWT_SECRET_KEY = 'test_jwt_key'

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    # En Docker local (HTTP), necesitamos False. En Prod real (HTTPS), True.
    # FORZADO A FALSE PARA DEBUGGING
    SESSION_COOKIE_SECURE = False 
    REMEMBER_COOKIE_SECURE = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        # En produccion podriamos loguear alertas si faltan variables criticas

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
