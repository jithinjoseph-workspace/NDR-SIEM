import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
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
import { Subscription } from 'rxjs';

interface TenantUser {
  id: string;
  username: string;
  role: string;
  tenant_id: string;
  created_at?: string;
  active?: boolean;
  permissions?: string[] | string;
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
export class TenantAdmin implements OnInit, OnDestroy {
  UsersIcon = Users;
  UserPlusIcon = UserPlus;
  ShieldIcon = ShieldCheck;
  LockIcon = Lock;
  EditIcon = Edit;
  TrashIcon = Trash2;
  XIcon = X;
  SaveIcon = Save;

  activeTab: 'users' = 'users';
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
  usernameStatus: 'idle' | 'checking' | 'available' | 'taken' | 'unavailable' = 'idle';
  private usernameTimer: ReturnType<typeof setTimeout> | null = null;
  private usernameCheckSub: Subscription | null = null;
  private readonly usernamePattern = /^[A-Za-z0-9._-]+$/;

  permissionOptions: PermissionOption[] = [
    { key: 'dashboard', label: 'Dashboard', description: 'Operational overview and metrics' },
    { key: 'alerts', label: 'Alerts', description: 'Correlation hits and alert triage' },
    { key: 'logs', label: 'Network Logs', description: 'Agent-Z and Agent-S event records' },
    { key: 'live', label: 'Live Stream', description: 'Real-time network activity' },
    { key: 'network-map', label: 'Network Map', description: 'Source and destination topology' },
    { key: 'intel', label: 'Threat Intel', description: 'IOC lookup and enrichment' },
    { key: 'health', label: 'System Health', description: 'Service and sensor status' },
    { key: 'rules', label: 'Rules View', description: 'Read-only detection rule access' },
    { key: 'soar', label: 'SOAR View', description: 'Read-only automation visibility' },
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
    active: true,
    permissions: [
      'dashboard',
      'alerts',
      'logs',
      'live',
      'network-map',
      'intel',
      'health',
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

  ngOnDestroy(): void {
    this.clearUsernameCheck();
  }

  get activeUsers() {
    return this.users.filter(user => user.active !== false).length;
  }

  get analystUsers() {
    return this.users.filter(user => user.role === 'analyst' || user.role === 'senior_analyst').length;
  }

  get viewerUsers() {
    return this.users.filter(user => user.role === 'viewer').length;
  }

  get pageTitle() {
    return 'Tenant Users';
  }

  get pageSubtitle() {
    return `Manage analysts and page access for ${this.tenantName}.`;
  }

  get usernameError() {
    return this.validateUsername(this.userForm.username);
  }

  get usernameFeedback() {
    if (this.editingUser || this.usernameError) return '';
    if (this.usernameStatus === 'checking') return 'Checking username availability...';
    if (this.usernameStatus === 'available') return 'Username is available';
    if (this.usernameStatus === 'taken') return 'Username already exists';
    if (this.usernameStatus === 'unavailable') return 'Could not check username availability';
    return '';
  }

  get usernameFeedbackType(): 'neutral' | 'success' | 'error' {
    if (this.usernameStatus === 'available') return 'success';
    if (this.usernameStatus === 'taken' || this.usernameStatus === 'unavailable') return 'error';
    return 'neutral';
  }

  get passwordErrors() {
    return this.validatePassword(
      this.userForm.password,
      this.userForm.username,
      !this.editingUser
    );
  }

  get canSaveUser() {
    return (
      !this.saving &&
      !this.usernameError &&
      this.passwordErrors.length === 0 &&
      (this.editingUser || this.usernameStatus === 'available')
    );
  }

  loadUsers() {
    this.loading = true;
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.users = (data.users || [])
          .filter((user: TenantUser) => user.tenant_id === this.tenantId)
          .filter((user: TenantUser) => this.isManageableTenantUser(user))
          .map((user: TenantUser) => ({
            ...user,
            // active comes directly from the database — no localStorage override
            active: user.active !== false,
            permissions: this.normalizePermissions(user.permissions, user.role),
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
    this.clearUsernameCheck();
    this.editingUser = null;
    this.userForm = {
      username: '',
      password: '',
      role: 'analyst',
      active: true,
      permissions: this.defaultPermissionsFor('analyst'),
    };
    this.showForm = true;
  }

  openEditForm(user: TenantUser) {
    this.clearUsernameCheck();
    this.editingUser = user;
    this.userForm = {
      username: user.username,
      password: '',
      role: user.role,
      active: user.active !== false,
      permissions: this.normalizePermissions(user.permissions, user.role),
    };
    this.showForm = true;
  }

  closeForm() {
    this.clearUsernameCheck();
    this.showForm = false;
  }

  onUsernameChange() {
    this.clearUsernameCheck();

    if (this.editingUser || this.usernameError) {
      this.usernameStatus = 'idle';
      this.cdr.detectChanges();
      return;
    }

    const username = this.userForm.username.trim();
    this.usernameStatus = 'checking';
    this.cdr.detectChanges();

    this.usernameTimer = setTimeout(() => {
      this.usernameCheckSub = this.auth.checkUsername(username).subscribe({
        next: (res) => {
          if (this.userForm.username.trim() !== username) return;
          this.usernameStatus = res.exists ? 'taken' : 'available';
          this.cdr.detectChanges();
        },
        error: () => {
          if (this.userForm.username.trim() !== username) return;
          this.usernameStatus = 'unavailable';
          this.cdr.detectChanges();
        },
      });
    }, 400);
  }

  saveUser() {
    const validationError = this.firstValidationError();
    if (validationError) {
      this.showMessage(validationError, 'error');
      return;
    }

    if (this.editingUser) {
      this.saving = true;
      const permissions = this.normalizePermissions(this.userForm.permissions, this.userForm.role);
      const userId = this.editingUser.id;
      const wasActive = this.editingUser.active !== false;
      const nowActive = this.userForm.active;
      const statusChanged = wasActive !== nowActive;

      // Step 1: Update permissions
      this.api.updateUserPermissions(userId, permissions).subscribe({
        next: (data: any) => {
          if (data.status !== 'ok') {
            this.saving = false;
            this.showMessage(data.message || 'Failed to update user access', 'error');
            this.cdr.detectChanges();
            return;
          }

          // Step 2: Update active status in the database if it changed
          const afterPermissions = () => {
            if (statusChanged) {
              this.api.setUserStatus(userId, nowActive).subscribe({
                next: (statusData: any) => {
                  if (statusData.status === 'ok') {
                    this.afterSaveComplete(userId, permissions, nowActive);
                  } else {
                    this.saving = false;
                    this.showMessage(statusData.message || 'Permissions saved but failed to update status', 'error');
                    this.cdr.detectChanges();
                  }
                },
                error: () => {
                  this.saving = false;
                  this.showMessage('Permissions saved but failed to update status', 'error');
                  this.cdr.detectChanges();
                }
              });
            } else {
              this.afterSaveComplete(userId, permissions, nowActive);
            }
          };

          // Step 3: Reset password if provided
          if (this.userForm.password.trim()) {
            this.api.resetUserPassword(userId, this.userForm.password).subscribe({
              next: (pwdData: any) => {
                if (pwdData.status === 'ok') {
                  afterPermissions();
                } else {
                  this.saving = false;
                  this.showMessage(pwdData.message || 'Access updated, but failed to reset password', 'error');
                  this.cdr.detectChanges();
                }
              },
              error: () => {
                this.saving = false;
                this.showMessage('Access updated, but failed to reset password', 'error');
                this.cdr.detectChanges();
              }
            });
          } else {
            afterPermissions();
          }
        },
        error: () => {
          this.saving = false;
          this.showMessage('Failed to update user access', 'error');
          this.cdr.detectChanges();
        },
      });
      return;
    }

    // Create new user
    this.saving = true;
    const permissions = this.normalizePermissions(this.userForm.permissions, this.userForm.role);
    this.api.createUser({
      username: this.userForm.username.trim(),
      password: this.userForm.password,
      role: this.userForm.role,
      tenant_id: this.tenantId,
      permissions,
    }).subscribe({
      next: (data: any) => {
        this.saving = false;
        if (data.status === 'ok') {
          this.closeForm();
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

  private afterSaveComplete(userId: string, permissions: string[], active: boolean) {
    this.saving = false;
    // Update local user list to reflect changes immediately
    this.users = this.users.map(user =>
      user.id === userId
        ? { ...user, permissions, active }
        : user
    );
    this.closeForm();
    this.showMessage(
      active ? 'User updated successfully' : 'User disabled successfully',
      'success'
    );
    this.cdr.detectChanges();
  }

  deleteUser(user: TenantUser) {
    if (!confirm(`Delete user "${user.username}" from this tenant?`)) return;
    this.api.deleteUser(user.id).subscribe({
      next: () => {
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
    return user.active !== false ? 'active' : 'disabled';
  }

  getRoleLabel(role: string) {
    return this.roleOptions.find(option => option.value === role)?.label || role;
  }

  getPermissionLabels(user: TenantUser) {
    const permissions = this.normalizePermissions(user.permissions, user.role);
    return this.permissionOptions
      .filter(option => permissions.includes(option.key))
      .map(option => option.label);
  }

  private defaultPermissionsFor(role: string): string[] {
    if (role === 'viewer') {
      return ['dashboard', 'alerts', 'health'];
    }
    if (role === 'senior_analyst') {
      return this.permissionOptions.map(option => option.key);
    }
    return [
      'dashboard',
      'alerts',
      'logs',
      'live',
      'network-map',
      'intel',
      'health',
    ];
  }

  private normalizePermissions(value: unknown, role: string): string[] {
    const permissions = Array.isArray(value)
      ? value
      : typeof value === 'string'
        ? value.split(',')
        : this.defaultPermissionsFor(role);

    return Array.from(new Set(permissions
      .map(permission => String(permission).trim())
      .filter(Boolean)
      .map(permission => permission.endsWith(':view')
        ? permission.replace(':view', '')
        : permission
      )
      .map(permission => permission === 'network' ? 'network-map' : permission)));
  }

  private isManageableTenantUser(user: TenantUser) {
    const adminRoles = ['admin', 'super_admin', 'tenant_admin'];
    if (adminRoles.includes(user.role)) return false;

    return user.id !== this.currentUser?.id && user.username !== this.currentUser?.username;
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

  private validateUsername(username: string) {
    const value = username.trim();
    if (!value) return 'Username is required';
    if (value.length < 3) return 'Username must be at least 3 characters';
    if (value.length > 50) return 'Username must be 50 characters or less';
    if (!this.usernamePattern.test(value)) {
      return 'Username can use letters, numbers, dot, underscore, and hyphen only';
    }
    if (!this.editingUser && this.localUsernameExists(value)) return 'Username already exists';
    return '';
  }

  private validatePassword(password: string, username: string, required: boolean) {
    const value = password || '';
    const errors: string[] = [];

    if (!value) {
      if (required) errors.push('Password is required');
      return errors;
    }

    if (value.length < 8) errors.push('Password must be at least 8 characters');
    if (!/[A-Z]/.test(value)) errors.push('Password needs an uppercase letter');
    if (!/[a-z]/.test(value)) errors.push('Password needs a lowercase letter');
    if (!/[0-9]/.test(value)) errors.push('Password needs a number');
    if (!/[^A-Za-z0-9]/.test(value)) errors.push('Password needs a special character');
    if (username.trim() && value.toLowerCase() === username.trim().toLowerCase()) {
      errors.push('Password cannot be the same as username');
    }

    return errors;
  }

  private firstValidationError() {
    if (this.usernameError) return this.usernameError;
    if (!this.editingUser && this.usernameStatus === 'checking') return 'Wait for username availability check';
    if (!this.editingUser && this.usernameStatus === 'taken') return 'Username already exists';
    if (!this.editingUser && this.usernameStatus === 'unavailable') {
      return 'Could not check username availability';
    }
    if (!this.editingUser && this.usernameStatus !== 'available') return 'Confirm username availability';
    return this.passwordErrors[0] || '';
  }

  private localUsernameExists(username: string) {
    const normalized = username.trim().toLowerCase();
    return this.users.some(user => user.username?.trim().toLowerCase() === normalized);
  }

  private clearUsernameCheck() {
    if (this.usernameTimer) {
      clearTimeout(this.usernameTimer);
      this.usernameTimer = null;
    }
    this.usernameCheckSub?.unsubscribe();
    this.usernameCheckSub = null;
    this.usernameStatus = 'idle';
  }
}
