import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  const isAuthEndpoint = req.url.includes('/auth/login') || req.url.includes('/auth/logout');

  // Block outgoing API requests immediately after logout — prevents in-flight
  // requests from hitting the wire and appearing as 401s in the Network tab.
  if (!isAuthEndpoint && !auth.isLoggedIn()) {
    return throwError(() => new HttpErrorResponse({ status: 401, statusText: 'Unauthorized' }));
  }

  // withCredentials: true sends the httpOnly cookie on every request.
  const authReq = req.clone({ withCredentials: true });

  return next(authReq).pipe(
    catchError(err => {
      if (err.status === 401 && !isAuthEndpoint && auth.isLoggedIn()) {
        auth.logout();
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