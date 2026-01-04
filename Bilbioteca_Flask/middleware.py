from flask import request, current_app, jsonify
import time

# Almacenamiento en memoria para los buckets: { ip: { 'tokens': float, 'last_updated': float } }
_buckets = {}

def check_rate_limit(ip):
    """
    Implementación del algoritmo Token Bucket.
    Retorna True si la petición es permitida, False si excede el límite.
    """
    # Obtener configuración desde la aplicación actual
    capacity = current_app.config.get('RATELIMIT_CAPACITY', 10)
    refill_rate = current_app.config.get('RATELIMIT_REFILL_RATE', 1.0)

    now = time.time()
    bucket = _buckets.get(ip)

    if bucket is None:
        # Primera vez que vemos esta IP, inicializamos lleno
        bucket = {
            'tokens': capacity,
            'last_updated': now
        }
        _buckets[ip] = bucket
    
    # 1. Calcular recarga (Lazy Refill)
    time_passed = now - bucket['last_updated']
    refill_amount = time_passed * refill_rate
    
    # 2. Actualizar tokens (sin exceder capacidad)
    bucket['tokens'] = min(capacity, bucket['tokens'] + refill_amount)
    bucket['last_updated'] = now
    
    # 3. Intentar consumir un token
    if bucket['tokens'] >= 1:
        bucket['tokens'] -= 1
        return True
    else:
        return False

def register_middleware(app):
    """
    Registra los middlewares globales de la aplicación.
    """
    
    @app.before_request
    def intercept_request():
        """
        Middleware para interceptar todas las peticiones entrantes.
        Se utiliza para controles de seguridad como Rate Limiting.
        """
        # 1. Identificar al cliente por IP
        # Nota: En entornos detrás de proxy (Docker, Nginx), usar request.headers.get('X-Forwarded-For')
        client_ip = request.remote_addr
        
        # 2. Aplicar Rate Limiting (Token Bucket)
        if not check_rate_limit(client_ip):
            # Registro técnico del bloqueo (Log)
            current_app.logger.warning(
                f"RATE_LIMIT_BLOCK: IP={client_ip} | Endpoint={request.path} | Method={request.method} | Reason=TokenBucketExhausted"
            )

            response = jsonify({
                'error': 'Too Many Requests',
                'message': 'Ha excedido el límite de solicitudes permitidas. Por favor espere.'
            })
            response.status_code = 429
            return response
        #     return jsonify({'error': 'Too Many Requests'}), 429
        
        # Si retorna None, Flask continúa con el procesamiento normal
        return None
