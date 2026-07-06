import { CanActivateFn, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './auth';
import { catchError, map, of } from 'rxjs';

export const authGuard: CanActivateFn = (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  
  if (!auth.isLoggedIn()) {
    router.navigate(['/login'], { replaceUrl: true });
    return false;
  }

  return auth.refreshUser().pipe(
    map((res: any) => {
      if (res.status !== 'ok') {
        auth.logout();
        return false;
      }

      const requiredRole = route.data?.['role'];
      const requiredPermission = route.data?.['permission'];
      if (!requiredRole) {
        if (requiredPermission && !auth.hasPermission(requiredPermission)) {
          router.navigate([auth.getDefaultRoute()]);
          return false;
        }
        return true;
      }

      const isAdmin = auth.isAdmin();
      if (requiredRole === 'admin' && !isAdmin) {
        router.navigate([auth.getDefaultRoute()]);
        return false;
      }

      if (requiredRole === 'analyst' && isAdmin) {
        router.navigate([auth.getDefaultRoute()]);
        return false;
      }

      if (requiredPermission && !auth.hasPermission(requiredPermission)) {
        router.navigate([auth.getDefaultRoute()]);
        return false;
      }

      return true;
    }),
    catchError(() => {
      auth.logout();
      return of(false);
    })
  );
};
