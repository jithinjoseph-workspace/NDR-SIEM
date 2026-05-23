import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private baseUrl = '/api';
  private TOKEN_KEY = 'ndr_token';
  private USER_KEY = 'ndr_user';
  private readonly defaultRouteByPermission: Record<string, string> = {
    dashboard: '/dashboard',
    alerts: '/alerts',
    logs: '/logs',
    live: '/live',
    'network-map': '/network-map',
    rules: '/rules',
    intel: '/intel',
    health: '/health',
    setup: '/setup',
    soar: '/soar',
    settings: '/settings',
  };

  constructor(
    private http: HttpClient,
    private router: Router
  ) {}

  login(username: string, password: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/login`, {
      username, password
    }).pipe(
      tap((res: any) => {
        if (res.token) {
          localStorage.setItem(this.TOKEN_KEY, res.token);
          localStorage.setItem(this.USER_KEY, JSON.stringify({
            ...res.user,
            permissions: this.normalizePermissions(res.user?.permissions),
          }));
        }
      })
    );
  }

  logout() {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
    sessionStorage.clear();
    this.router.navigate(['/login'], { replaceUrl: true });
  }

  getToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  refreshUser(): Observable<any> {
    return this.http.get(`${this.baseUrl}/auth/me`).pipe(
      tap((res: any) => {
        if (res.status === 'ok' && res.user) {
          localStorage.setItem(this.USER_KEY, JSON.stringify({
            ...res.user,
            permissions: this.normalizePermissions(res.user.permissions),
          }));
        }
      })
    );
  }

  getUser(): any {
    const u = localStorage.getItem(this.USER_KEY);
    if (!u) return null;

    try {
      const user = JSON.parse(u);
      return {
        ...user,
        permissions: this.normalizePermissions(user?.permissions),
      };
    } catch {
      return null;
    }
  }

  isLoggedIn(): boolean {
    const token = this.getToken();
    if (!token) return false;
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp > Date.now() / 1000;
    } catch { return false; }
  }

  /** Returns milliseconds until the JWT expires. Negative means already expired. */
  getTokenExpiresInMs(): number {
    const token = this.getToken();
    if (!token) return -1;
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp * 1000 - Date.now();
    } catch { return -1; }
  }

  isAdmin(): boolean {
    const role = this.getUser()?.role;
    return role === 'admin' || role === 'super_admin';
  }

  hasPermission(permission: string): boolean {
    const user = this.getUser();
    if (!user) return false;
    if (this.isAdmin() || user.role === 'tenant_admin') return true;

    return this.normalizePermissions(user.permissions).includes(permission);
  }

  getDefaultRoute(): string {
    const user = this.getUser();
    if (!user) return '/login';
    if (this.isAdmin()) return '/admin';
    if (user.role === 'tenant_admin') return '/tenant-admin';

    const permissions = this.normalizePermissions(user.permissions);
    const firstPermission = permissions.find(permission => this.defaultRouteByPermission[permission]);
    return firstPermission ? this.defaultRouteByPermission[firstPermission] : '/settings';
  }

  normalizePermissions(value: unknown): string[] {
    const rawPermissions = Array.isArray(value)
      ? value
      : typeof value === 'string'
        ? value.split(',')
        : [];

    return Array.from(new Set(rawPermissions
      .map(permission => String(permission).trim())
      .filter(Boolean)
      .map(permission => permission.endsWith(':view')
        ? permission.replace(':view', '')
        : permission
      )
      .map(permission => permission === 'network' ? 'network-map' : permission)));
  }
}
