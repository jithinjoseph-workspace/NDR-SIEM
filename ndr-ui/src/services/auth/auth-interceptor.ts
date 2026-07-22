import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const token = auth.getToken();

  const authReq = token ? req.clone({
    setHeaders: { Authorization: `Bearer ${token}` }
  }) : req;

  return next(authReq).pipe(
    catchError(err => {
      // Session expired or token invalid → standard logout
      if (err.status === 401) {
        auth.logout();
        router.navigate(['/login']);
      }

      // Account disabled by Tenant Admin while session was live.
      // Backend returns HTTP 403 with { code: "USER_DISABLED" }.
      // Force-logout immediately so the user is evicted from their current page.
      if (err.status === 403 && err.error?.code === 'USER_DISABLED') {
        auth.logout();
      }

      return throwError(() => err);
    })
  );
};