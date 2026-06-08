import { Component, ChangeDetectorRef, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth/auth';
import { Websocket } from '../../services/websocket/websocket';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './login.html',
  styleUrl: './login.css'
})
export class Login implements OnDestroy {
  username = '';
  password = '';
  loading = false;
  error = '';
  showPassword = false;

  // ── Live username check ──────────────────────────────────────────────────
  usernameStatus: 'idle' | 'checking' | 'found' | 'not_found' = 'idle';
  private usernameTimer: any = null;
  private usernameCheckSub: Subscription | null = null;

  constructor(
    private auth: AuthService,
    private router: Router,
    private cdr: ChangeDetectorRef,
    private ws: Websocket
  ) {
    if (this.auth.isLoggedIn()) {
      this.router.navigate([this.auth.getDefaultRoute()]);
    }
  }

  ngOnDestroy(): void {
    clearTimeout(this.usernameTimer);
    this.usernameCheckSub?.unsubscribe();
  }

  /** Called on every keystroke in the username field. Debounces 400ms. */
  onUsernameChange(): void {
    clearTimeout(this.usernameTimer);
    this.usernameCheckSub?.unsubscribe();

    if (!this.username.trim()) {
      this.usernameStatus = 'idle';
      this.cdr.detectChanges();
      return;
    }

    this.usernameStatus = 'checking';
    this.cdr.detectChanges();

    this.usernameTimer = setTimeout(() => {
      this.usernameCheckSub = this.auth.checkUsername(this.username.trim()).subscribe({
        next: (res) => {
          this.usernameStatus = res.exists ? 'found' : 'not_found';
          this.cdr.detectChanges();
        },
        error: () => {
          // Network error — silently reset; don't block the user from trying to log in
          this.usernameStatus = 'idle';
          this.cdr.detectChanges();
        }
      });
    }, 400);
  }

  login() {
    if (!this.username || !this.password) {
      this.error = 'Please enter username and password';
      return;
    }
    this.loading = true;
    this.error = '';
    this.cdr.detectChanges();

    this.auth.login(this.username, this.password).subscribe({
      next: (res: any) => {
        this.loading = false;
        if (res.token) {
          const role = res.user?.role;
          if (role === 'admin' || role === 'super_admin') {
            this.router.navigate(['/admin']).then(() => {
              this.ws.connect();
            });
          } else if (role === 'tenant_admin') {
            this.router.navigate(['/tenant-admin']).then(() => {
              this.ws.connect();
            });
          } else {
            this.router.navigate([this.auth.getDefaultRoute()]).then(() => {
              this.ws.connect();
            });
          }
        } else {
          // status: "error" returned with 200 OK (should not happen now, but fallback)
          this.error = res.message || 'Login failed';
        }
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        // HTTP 403 = account disabled by administrator
        if (err.status === 403) {
          this.error = err.error?.message ||
            'Your account has been disabled. Please contact your administrator.';
        } else if (err.status === 401) {
          this.error = 'Invalid username or password';
        } else {
          this.error = err.error?.message ||
            'Login failed. Please try again.';
        }
        this.cdr.detectChanges();
      }
    });
  }
}

