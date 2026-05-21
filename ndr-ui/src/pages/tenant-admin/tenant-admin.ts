import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import {
  LucideAngularModule,
  Users,
  UserPlus,
  ShieldCheck,
  Lock,
  Edit,
  Trash2,
  X,
  Save,
} from 'lucide-angular';
import { Api } from '../../services/api/api';
import { AuthService } from '../../services/auth/auth';

interface TenantUser {
  id: string;
  username: string;
  role: string;
  tenant_id: string;
  created_at?: string;
  status?: 'active' | 'disabled';
  permissions?: string[];
}

interface PermissionOption {
  key: string;
  label: string;
  description: string;
}

@Component({
  selector: 'app-tenant-admin',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './tenant-admin.html',
  styleUrl: './tenant-admin.css',
})
export class TenantAdmin implements OnInit {
  UsersIcon = Users;
  UserPlusIcon = UserPlus;
  ShieldIcon = ShieldCheck;
  LockIcon = Lock;
  EditIcon = Edit;
  TrashIcon = Trash2;
  XIcon = X;
  SaveIcon = Save;

  currentUser: any = {};
  tenantId = '';
  tenantName = 'Organization';
  users: TenantUser[] = [];
  loading = false;
  saving = false;
  showForm = false;
  editingUser: TenantUser | null = null;
  message = '';
  messageType: 'success' | 'error' = 'success';

  permissionOptions: PermissionOption[] = [
    { key: 'dashboard:view', label: 'Dashboard', description: 'Operational overview and metrics' },
    { key: 'alerts:view', label: 'Alerts', description: 'Correlation hits and alert triage' },
    { key: 'logs:view', label: 'Network Logs', description: 'Zeek and Suricata event records' },
    { key: 'live:view', label: 'Live Stream', description: 'Real-time network activity' },
    { key: 'network:view', label: 'Network Map', description: 'Source and destination topology' },
    { key: 'intel:view', label: 'Threat Intel', description: 'IOC lookup and enrichment' },
    { key: 'health:view', label: 'System Health', description: 'Service and sensor status' },
    { key: 'rules:view', label: 'Rules View', description: 'Read-only detection rule access' },
    { key: 'soar:view', label: 'SOAR View', description: 'Read-only automation visibility' },
  ];

  roleOptions = [
    { value: 'analyst', label: 'Analyst' },
    { value: 'senior_analyst', label: 'Senior Analyst' },
    { value: 'viewer', label: 'Viewer' },
  ];

  userForm = {
    username: '',
    password: '',
    role: 'analyst',
    status: 'active' as 'active' | 'disabled',
    permissions: [
      'dashboard:view',
      'alerts:view',
      'logs:view',
      'live:view',
      'network:view',
      'intel:view',
      'health:view',
    ] as string[],
  };

  constructor(
    private api: Api,
    private auth: AuthService,
    private router: Router,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.currentUser = this.auth.getUser() || {};
    this.tenantId = this.currentUser.tenant_id || 'default';
    this.tenantName = this.formatTenantName(this.tenantId);

    const allowed = ['admin', 'tenant_admin'].includes(this.currentUser.role);
    if (!allowed || this.tenantId === 'default') {
      this.router.navigate(['/dashboard']);
      return;
    }

    this.loadUsers();
  }

  get activeUsers() {
    return this.users.filter(user => this.getUserStatus(user) === 'active').length;
  }

  get analystUsers() {
    return this.users.filter(user => user.role === 'analyst' || user.role === 'senior_analyst').length;
  }

  get viewerUsers() {
    return this.users.filter(user => user.role === 'viewer').length;
  }

  loadUsers() {
    this.loading = true;
    this.api.getUsers().subscribe({
      next: (data: any) => {
        const permissionMap = this.getPermissionMap();
        this.users = (data.users || [])
          .filter((user: TenantUser) => user.tenant_id === this.tenantId)
          .filter((user: TenantUser) => user.role !== 'admin' && user.role !== 'super_admin')
          .map((user: TenantUser) => ({
            ...user,
            role: permissionMap[user.id]?.role || user.role,
            status: permissionMap[user.id]?.status || 'active',
            permissions: permissionMap[user.id]?.permissions || this.defaultPermissionsFor(
              permissionMap[user.id]?.role || user.role
            ),
          }));
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.showMessage('Failed to load tenant users', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  openCreateForm() {
    this.editingUser = null;
    this.userForm = {
      username: '',
      password: '',
      role: 'analyst',
      status: 'active',
      permissions: this.defaultPermissionsFor('analyst'),
    };
    this.showForm = true;
  }

  openEditForm(user: TenantUser) {
    this.editingUser = user;
    this.userForm = {
      username: user.username,
      password: '',
      role: user.role,
      status: this.getUserStatus(user),
      permissions: [...(user.permissions || this.defaultPermissionsFor(user.role))],
    };
    this.showForm = true;
  }

  saveUser() {
    if (!this.userForm.username.trim()) {
      this.showMessage('Username is required', 'error');
      return;
    }

    if (!this.editingUser && !this.userForm.password.trim()) {
      this.showMessage('Password is required for a new user', 'error');
      return;
    }

    if (this.editingUser) {
      this.applyLocalUserSettings(this.editingUser.id);
      this.showForm = false;
      this.showMessage('User access updated', 'success');
      return;
    }

    this.saving = true;
    this.api.createUser({
      username: this.userForm.username.trim(),
      password: this.userForm.password,
      role: this.userForm.role,
      tenant_id: this.tenantId,
    }).subscribe({
      next: (data: any) => {
        this.saving = false;
        if (data.status === 'ok') {
          this.showForm = false;
          this.showMessage('User created for this tenant', 'success');
          this.loadUsers();
        } else {
          this.showMessage(data.message || 'Failed to create user', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.saving = false;
        this.showMessage('Failed to create user', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  deleteUser(user: TenantUser) {
    if (!confirm(`Delete user "${user.username}" from this tenant?`)) return;
    this.api.deleteUser(user.id).subscribe({
      next: () => {
        this.removeLocalUserSettings(user.id);
        this.users = this.users.filter(item => item.id !== user.id);
        this.showMessage('User deleted', 'success');
        this.cdr.detectChanges();
      },
      error: () => this.showMessage('Failed to delete user', 'error'),
    });
  }

  togglePermission(permission: string) {
    const selected = new Set(this.userForm.permissions);
    if (selected.has(permission)) {
      selected.delete(permission);
    } else {
      selected.add(permission);
    }
    this.userForm.permissions = Array.from(selected);
  }

  hasPermission(permission: string) {
    return this.userForm.permissions.includes(permission);
  }

  onRoleChange() {
    if (!this.editingUser) {
      this.userForm.permissions = this.defaultPermissionsFor(this.userForm.role);
    }
  }

  getUserStatus(user: TenantUser): 'active' | 'disabled' {
    return user.status || 'active';
  }

  getRoleLabel(role: string) {
    return this.roleOptions.find(option => option.value === role)?.label || role;
  }

  getPermissionLabels(user: TenantUser) {
    const permissions = user.permissions || [];
    return this.permissionOptions
      .filter(option => permissions.includes(option.key))
      .map(option => option.label);
  }

  private defaultPermissionsFor(role: string): string[] {
    if (role === 'viewer') {
      return ['dashboard:view', 'alerts:view', 'health:view'];
    }
    if (role === 'senior_analyst') {
      return this.permissionOptions.map(option => option.key);
    }
    return [
      'dashboard:view',
      'alerts:view',
      'logs:view',
      'live:view',
      'network:view',
      'intel:view',
      'health:view',
    ];
  }

  private applyLocalUserSettings(userId: string) {
    const permissionMap = this.getPermissionMap();
    permissionMap[userId] = {
      role: this.userForm.role,
      status: this.userForm.status,
      permissions: [...this.userForm.permissions],
    };
    localStorage.setItem(this.permissionStorageKey(), JSON.stringify(permissionMap));
    this.users = this.users.map(user =>
      user.id === userId
        ? {
            ...user,
            role: this.userForm.role,
            status: this.userForm.status,
            permissions: [...this.userForm.permissions],
          }
        : user
    );
  }

  private removeLocalUserSettings(userId: string) {
    const permissionMap = this.getPermissionMap();
    delete permissionMap[userId];
    localStorage.setItem(this.permissionStorageKey(), JSON.stringify(permissionMap));
  }

  private getPermissionMap(): Record<string, { role?: string; status: 'active' | 'disabled'; permissions: string[] }> {
    try {
      return JSON.parse(localStorage.getItem(this.permissionStorageKey()) || '{}');
    } catch {
      return {};
    }
  }

  private permissionStorageKey() {
    return `ndr_tenant_permissions_${this.tenantId}`;
  }

  private showMessage(message: string, type: 'success' | 'error') {
    this.message = message;
    this.messageType = type;
    setTimeout(() => {
      this.message = '';
      this.cdr.detectChanges();
    }, 5000);
  }

  private formatTenantName(tenantId: string) {
    return tenantId
      .split(/[-_]/)
      .filter(Boolean)
      .map(part => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ') || 'Organization';
  }
}
