import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { AuthService } from '../../services/auth/auth';
import { Router } from '@angular/router';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './admin.html',
  styleUrl: './admin.css'
})
export class Admin implements OnInit {
  activeTab = 'users';
  
  // Users
  users: any[] = [];
  loadingUsers = false;
  showAddUser = false;
  newUser = {
    username: '',
    password: '',
    role: 'tenant_admin',
    tenant_id: ''
  };
  savingUser = false;
  userMsg = '';
  userMsgType = '';

  // Tenants
  tenants: any[] = [];
  loadingTenants = false;
  showAddTenant = false;
  newTenant = {
    name: '',
    id: ''
  };
  savingTenant = false;
  tenantMsg = '';

  // Engines
  engines: any[] = [];
  loadingEngines = false;
  scaling = false;

  // Current user
  currentUser: any = {};

  constructor(
    private api: Api,
    private auth: AuthService,
    private router: Router,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.currentUser = this.auth.getUser();
    if (!this.auth.isAdmin()) {
      this.router.navigate(['/dashboard']);
      return;
    }
    this.loadUsers();
    this.loadTenants();
    this.loadEngines();
  }

  loadUsers() {
    this.loadingUsers = true;
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.users = data.users || [];
        this.loadingUsers = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingUsers = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadTenants() {
    this.loadingTenants = true;
    this.api.getTenants().subscribe({
      next: (data: any) => {
        this.tenants = data.tenants || [];
        this.loadingTenants = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingTenants = false;
        this.cdr.detectChanges();
      }
    });
  }

  addUser() {
    if (!this.newUser.username || !this.newUser.password) {
      this.showMsg('Username and password required', 'error');
      return;
    }
    if (!this.newUser.tenant_id || this.newUser.tenant_id === 'default') {
      this.showMsg('Select a tenant for the Tenant Admin', 'error');
      return;
    }
    this.savingUser = true;
    this.api.createUser({
      ...this.newUser,
      role: 'tenant_admin'
    }).subscribe({
      next: (data: any) => {
        this.savingUser = false;
        if (data.status === 'ok') {
          this.showAddUser = false;
          this.newUser = {
            username: '', password: '',
            role: 'tenant_admin', tenant_id: ''
          };
          this.loadUsers();
          this.showMsg('✅ User created!', 'success');
        } else {
          this.showMsg(data.message, 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.savingUser = false;
        this.showMsg('Failed to create user', 'error');
        this.cdr.detectChanges();
      }
    });
  }

  deleteUser(user: any) {
    if (!confirm(`Delete user "${user.username}"?`)) return;
    this.api.deleteUser(user.id).subscribe({
      next: () => {
        this.loadUsers();
        this.showMsg('User deleted', 'success');
      }
    });
  }

  addTenant() {
    if (!this.newTenant.name) {
      this.tenantMsg = 'Tenant name required';
      return;
    }
    this.newTenant.id = this.newTenant.name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '-');
    this.savingTenant = true;
    this.api.createTenant(this.newTenant).subscribe({
      next: (data: any) => {
        this.savingTenant = false;
        if (data.status === 'ok') {
          this.showAddTenant = false;
          this.newTenant = { name: '', id: '' };
          this.loadTenants();
          this.tenantMsg = '✅ Tenant created!';
        } else {
          this.tenantMsg = data.message;
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.savingTenant = false;
        this.tenantMsg = 'Failed to create tenant';
        this.cdr.detectChanges();
      }
    });
  }

  showMsg(msg: string, type: string) {
    this.userMsg = msg;
    this.userMsgType = type;
    setTimeout(() => {
      this.userMsg = '';
      this.cdr.detectChanges();
    }, 5000);
  }

  getRoleBadge(role: string): string {
    switch(role) {
      case 'super_admin': return 'bg-red-500/20 text-red-400';
      case 'admin': return 'bg-red-500/20 text-red-400';
      case 'tenant_admin': return 'bg-amber-500/20 text-amber-300';
      case 'analyst': return 'bg-primary/20 text-primary';
      default: return 'bg-surface-container text-on-surface-variant';
    }
  }

  loadEngines() {
    this.loadingEngines = true;
    this.api.getEngines().subscribe({
      next: (data: any) => {
        this.engines = data.engines || [];
        this.loadingEngines = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingEngines = false;
        this.cdr.detectChanges();
      }
    });
  }

  scaleUp() {
    this.scaling = true;
    this.api.scaleEngines('up').subscribe({
      next: (data: any) => {
        this.scaling = false;
        this.showMsg(data.message, 'success');
        setTimeout(() => this.loadEngines(), 3000);
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.scaling = false;
        this.showMsg(err.error?.message || 'Failed to scale up', 'error');
        this.cdr.detectChanges();
      }
    });
  }

  scaleDown(engine: string) {
    if (!confirm(`Stop ${engine}?`)) return;
    this.api.scaleEngines('down', engine).subscribe({
      next: (data: any) => {
        this.showMsg(data.message, 'success');
        setTimeout(() => this.loadEngines(), 2000);
      },
      error: (err: any) => {
        this.showMsg(err.error?.message || 'Failed to scale down', 'error');
      }
    });
  }
}
