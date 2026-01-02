import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import Swal from 'sweetalert2'; // O tu sistema de notificaciones
@Injectable()
export class RateLimitInterceptor implements HttpInterceptor {

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        return next.handle(req).pipe(
            catchError((error: HttpErrorResponse) => {
                if (error.status === 429) {
                    Swal.fire({
                        icon: 'warning',
                        title: 'Demasiadas solicitudes',
                        text: 'Has realizado demasiadas solicitudes. Por favor, espera 15 minutos antes de intentar nuevamente.',
                        confirmButtonText: 'Entendido'
                    });
                } else if (error.status === 403) {
                    Swal.fire({
                        icon: 'error',
                        title: 'Acceso denegado',
                        text: 'Tu dirección IP ha sido bloqueada temporalmente por comportamiento sospechoso. Intenta más tarde o contacta al administrador.',
                        confirmButtonText: 'Entendido'
                    });
                }
                return throwError(() => error);
            })
        );
    }
}