import { CanActivateFn, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './auth';

export const authGuard: CanActivateFn = (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  
  if (!auth.isLoggedIn()) {
    router.navigate(['/login'], { replaceUrl: true });
    return false;
  }

  const requiredRole = route.data?.['role'];
  if (!requiredRole) {
    // No specific role required (e.g. settings page), just being logged in is enough
    return true;
  }

  const isAdmin = auth.isAdmin();
  if (requiredRole === 'admin' && !isAdmin) {
    // Standard user tries to access admin -> redirect to dashboard
    router.navigate(['/dashboard']);
    return false;
  }

  if (requiredRole === 'analyst' && isAdmin) {
    // Admin tries to access analyst pages -> redirect to admin panel
    router.navigate(['/admin']);
    return false;
  }

  return true;
};
