import { Component, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth/auth';
import { Websocket } from '../../services/websocket/websocket';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './login.html'
})
export class Login {
  username = '';
  password = '';
  loading = false;
  error = '';
  showPassword = false;

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
