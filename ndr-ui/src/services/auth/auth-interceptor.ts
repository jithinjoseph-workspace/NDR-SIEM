import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const token = auth.getToken();

  // withCredentials: true lets the browser send the httpOnly cookie on every
  // request and store Set-Cookie responses (login / logout).
  // The Authorization: Bearer header is still sent while localStorage has a
  // token — both auth paths remain active so neither client breaks.
  const authReq = req.clone({
    withCredentials: true,
    ...(token ? { setHeaders: { Authorization: `Bearer ${token}` } } : {})
  });

  return next(authReq).pipe(
    catchError(err => {
      // Session expired or token invalid → standard logout.
      // Skip logout for the login endpoint itself — a 401 there means wrong
      // password, not an expired session; the login component shows the error.
      const isLoginRequest = req.url.includes('/auth/login');
      if (err.status === 401 && !isLoginRequest) {
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