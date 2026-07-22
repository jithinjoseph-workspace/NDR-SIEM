import { Injectable, OnDestroy } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, of, tap, Subscription } from 'rxjs';
import { Websocket } from '../websocket/websocket';

@Injectable({ providedIn: 'root' })
export class AuthService implements OnDestroy {
  private baseUrl = '/api';
  private TOKEN_KEY = 'ndr_token';
  private USER_KEY = 'ndr_user';

  /**
   * How often to poll /api/auth/me to detect account blocking.
   * 30 seconds is a deliberate balance: quick enough to evict a blocked user
   * promptly, low enough to not meaningfully increase server load.
   */
  private readonly SESSION_POLL_MS = 30_000;
  private sessionPollInterval: ReturnType<typeof setInterval> | null = null;
  private sessionPollSub: Subscription | null = null;

  /** Timestamp (ms) of last successful user data write — used to skip a redundant
   *  /api/auth/me round-trip in authGuard immediately after login. */
  private userDataFreshAt = 0;

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
    evidence: '/evidence',
    assets: '/assets',
    'ai-activity': '/ai-activity',
    'ai-report': '/ai-report',
  };

  constructor(
    private http: HttpClient,
    private router: Router,
    private ws: Websocket
  ) { }

  ngOnDestroy(): void {
    this.stopSessionPoll();
  }

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
          this.userDataFreshAt = Date.now();
        }
      })
    );
  }

  /** True if user data was written within the last 10 seconds — authGuard can
   *  skip the /api/auth/me round-trip when this returns true. */
  isUserDataFresh(): boolean {
    return Date.now() - this.userDataFreshAt < 10_000;
  }

  /** Check if a username exists in the database (no auth required). */
  checkUsername(username: string): Observable<{ exists: boolean }> {
    return this.http.get<{ exists: boolean }>(
      `${this.baseUrl}/auth/check-username`,
      { params: { username } }
    );
  }


  logout() {
    // Stop polling before clearing state so any in-flight poll doesn't restart it
    this.stopSessionPoll();
    this.ws.disconnect();
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
    sessionStorage.clear();
    window.location.href = '/login';
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
          this.userDataFreshAt = Date.now();
        }
        // If backend returns USER_DISABLED via get_me (HTTP 200 with error body),
        // the authGuard already calls logout() when status !== 'ok'.
        // The auth-interceptor handles the 403 path (from auth_middleware).
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

  /**
   * Returns the sensor IDs the current user is scoped to.
   * Reads directly from the JWT payload since sensor_ids are baked in at login.
   * Returns [] for unrestricted users (admins / tenant_admins) or when no token exists.
   */
  getSensorIds(): string[] {
    const token = this.getToken();
    if (!token) return [];
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return Array.isArray(payload.sensor_ids) ? payload.sensor_ids : [];
    } catch { return []; }
  }

  isTenantAiEnabled(): boolean {
    const user = this.getUser();
    if (!user) return false;
    if (user.role === 'super_admin') return true;
    return user.ai_enabled !== false;
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

  // ── Session Poll ─────────────────────────────────────────────────────────

  /**
   * Start a recurring poll of /api/auth/me every SESSION_POLL_MS milliseconds.
   *
   * This is the primary mechanism for detecting a live-session block:
   *   - If the user is blocked, the backend returns { code: "USER_DISABLED" }
   *     which the authGuard's refreshUser() call treats as a non-ok status
   *     and calls logout().
   *   - Additionally auth_middleware returns HTTP 403 on any other API call,
   *     which the auth-interceptor catches and calls logout() for.
   *
   * Only meaningful for analyst/viewer roles — admins are never blocked.
   * Safe to call multiple times; only one interval is ever active.
   */
  startSessionPoll(): void {
    if (this.sessionPollInterval !== null) return; // already running

    this.sessionPollInterval = setInterval(() => {
      if (!this.isLoggedIn()) {
        // Token expired; clean up instead of spamming the backend
        this.stopSessionPoll();
        return;
      }

      // Reuse the same observable that authGuard uses.
      // The tap() inside refreshUser() updates localStorage on success.
      // On error: auth-interceptor handles 403 USER_DISABLED → logout().
      // On non-ok status (USER_DISABLED via 200): authGuard logic applies
      // on the next navigation; for immediate eviction we check here too.
      this.sessionPollSub?.unsubscribe();
      this.sessionPollSub = this.refreshUser().subscribe({
        next: (res: any) => {
          if (res.status !== 'ok') {
            // Covers USER_DISABLED returned as HTTP 200 from get_me
            this.logout();
          }
        },
        error: () => {
          // HTTP errors (401/403) are already handled by auth-interceptor.
          // No additional action needed here.
        }
      });
    }, this.SESSION_POLL_MS);
  }

  /**
   * Stop the session poll and clean up subscriptions.
   * Called automatically by logout() and ngOnDestroy().
   */
  stopSessionPoll(): void {
    if (this.sessionPollInterval !== null) {
      clearInterval(this.sessionPollInterval);
      this.sessionPollInterval = null;
    }
    this.sessionPollSub?.unsubscribe();
    this.sessionPollSub = null;
  }
}
