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
      if (this.auth.isAdmin()) {
        this.router.navigate(['/admin']);
      } else {
        this.router.navigate(['/dashboard']);
      }
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
          const tenantId = res.user?.tenant_id;
          if (role === 'admin' && tenantId === 'default') {
            this.router.navigate(['/admin']).then(() => {
              this.ws.connect();
            });
          } else if (role === 'admin' || role === 'tenant_admin') {
            this.router.navigate(['/tenant-admin']).then(() => {
              this.ws.connect();
            });
          } else {
            this.router.navigate(['/dashboard']).then(() => {
              this.ws.connect();
            });
          }
        } else {
          this.error = res.message || 'Login failed';
        }
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        this.error = err.error?.message ||
          'Invalid username or password';
        this.cdr.detectChanges();
      }
    });
  }
}
