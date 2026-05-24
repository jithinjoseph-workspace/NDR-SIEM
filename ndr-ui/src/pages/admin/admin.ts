import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Building2,
  CircleCheck,
  Edit,
  Gauge,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
  X,
} from 'lucide-angular';
import { Api } from '../../services/api/api';
import { AuthService } from '../../services/auth/auth';
import { Router } from '@angular/router';

@Component({
  selector: 'app-admin',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './admin.html',
  styleUrl: './admin.css',
})
export class Admin implements OnInit, OnDestroy {
  BuildingIcon = Building2;
  CheckIcon = CircleCheck;
  EditIcon = Edit;
  GaugeIcon = Gauge;
  PlusIcon = Plus;
  RefreshIcon = RefreshCw;
  SearchIcon = Search;
  ServerIcon = Server;
  ShieldIcon = ShieldCheck;
  TrashIcon = Trash2;
  UserPlusIcon = UserPlus;
  UsersIcon = Users;
  XIcon = X;

  activeTab = 'tenants';

  users: any[] = [];
  loadingUsers = false;
  showAddUser = false;
  userSearch = '';
  selectedTenant = 'all';
  pendingDeleteUser: any = null;
  editingUser: any = null;
  newUser = {
    username: '',
    password: '',
    role: 'tenant_admin',
    tenant_id: '',
  };
  userForm = {
    role: 'tenant_admin',
    tenant_id: '',
    active: true,
    password: '',
    permissions: '',
  };
  roleOptions = [
    { value: 'tenant_admin', label: 'Tenant Admin' },
    { value: 'default_user', label: 'Default User' },
    { value: 'admin', label: 'Platform Admin' },
    { value: 'senior_analyst', label: 'Senior Analyst' },
    { value: 'analyst', label: 'Analyst' },
    { value: 'viewer', label: 'Viewer' },
  ];
  createUserRoleOptions = [
    { value: 'tenant_admin', label: 'Tenant Admin' },
    { value: 'default_user', label: 'Default User' },
  ];
  savingUser = false;
  userMsg = '';
  userMsgType = '';

  tenants: any[] = [];
  loadingTenants = false;
  showAddTenant = false;
  tenantSearch = '';
  newTenant = {
    name: '',
    id: '',
  };
  savingTenant = false;
  tenantMsg = '';
  editingTenant: any = null;
  tenantForm = {
    name: '',
    active: true,
  };

  engines: any[] = [];
  loadingEngines = false;
  scaling = false;
  lastEngineRefresh: Date | null = null;
  pendingStopEngine = '';

  currentUser: any = {};
  /** Non-empty when the session is about to expire or has expired. */
  sessionExpiryWarning = '';
  private sessionCheckInterval: ReturnType<typeof setInterval> | null = null;

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
    this.startSessionExpiryCheck();
  }

  ngOnDestroy(): void {
    // Always clear the interval when the component is torn down
    // to avoid a dangling callback and potential memory leak.
    if (this.sessionCheckInterval !== null) {
      clearInterval(this.sessionCheckInterval);
    }
  }

  get tenantAdmins() {
    return this.users.filter(user => user.role === 'tenant_admin');
  }

  get managedUsers() {
    return this.users.filter(user => user.role !== 'super_admin');
  }

  get filteredTenantAdmins() {
    const query = this.userSearch.trim().toLowerCase();
    return this.managedUsers.filter(user => {
      const matchesTenant = this.selectedTenant === 'all' || user.tenant_id === this.selectedTenant;
      const matchesQuery =
        !query ||
        user.username?.toLowerCase().includes(query) ||
        user.role?.toLowerCase().includes(query) ||
        user.tenant_id?.toLowerCase().includes(query);
      return matchesTenant && matchesQuery;
    });
  }

  get selectedTenantName() {
    return this.selectedTenant === 'all'
      ? 'All tenants'
      : this.tenantName(this.selectedTenant);
  }

  get selectedTenantIsInactive() {
    return this.selectedTenant !== 'all' && this.isTenantInactive(this.selectedTenant);
  }

  get filteredTenants() {
    const query = this.tenantSearch.trim().toLowerCase();
    return this.tenants.filter(tenant => {
      if (!query) return true;
      return tenant.name?.toLowerCase().includes(query) || tenant.id?.toLowerCase().includes(query);
    });
  }

  get activeTenants() {
    return this.tenants.filter(tenant => tenant.active).length;
  }

  get canCreateTenant() {
    return (
      !!this.newTenant.name.trim() &&
      !!this.newTenant.id.trim() &&
      !this.tenantIdExists(this.newTenant.id)
    );
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
        this.showMsg('Failed to load users', 'error');
        this.cdr.detectChanges();
      },
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
        this.showMsg('Failed to load tenants', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  addUser() {
    if (!this.newUser.username || !this.newUser.password) {
      this.showMsg('Username and password required', 'error');
      return;
    }
    this.applyRoleTenantRules(this.newUser);
    if (this.newUser.role === 'tenant_admin' && (!this.newUser.tenant_id || this.newUser.tenant_id === 'default')) {
      this.showMsg('Select a tenant for the tenant admin', 'error');
      return;
    }

    this.savingUser = true;
    this.api
      .createUser({
        ...this.newUser,
        tenant_id: this.newUser.tenant_id || 'default',
      })
      .subscribe({
        next: (data: any) => {
          this.savingUser = false;
          if (data.status === 'ok') {
            this.showAddUser = false;
            this.newUser = {
              username: '',
              password: '',
              role: 'tenant_admin',
              tenant_id: '',
            };
            this.loadUsers();
            this.showMsg('Tenant admin created', 'success');
          } else {
            this.showMsg(data.message, 'error');
          }
          this.cdr.detectChanges();
        },
        error: () => {
          this.savingUser = false;
          this.showMsg('Failed to create tenant admin', 'error');
          this.cdr.detectChanges();
        },
      });
  }

  requestDeleteUser(user: any) {
    this.pendingDeleteUser = user;
  }

  cancelDeleteUser() {
    this.pendingDeleteUser = null;
  }

  confirmDeleteUser() {
    if (!this.pendingDeleteUser) return;
    const user = this.pendingDeleteUser;
    this.api.deleteUser(user.id).subscribe({
      next: () => {
        this.pendingDeleteUser = null;
        this.loadUsers();
        this.showMsg('Tenant admin deleted', 'success');
        this.cdr.detectChanges();
      },
      error: () => {
        this.showMsg('Failed to delete tenant admin', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  openEditUser(user: any) {
    this.editingUser = user;
    this.userForm = {
      role: user.role,
      tenant_id: user.tenant_id,
      active: user.active !== false,
      password: '',
      permissions: user.permissions || this.defaultPermissionsFor(user.role),
    };
  }

  closeEditUser() {
    this.editingUser = null;
  }

  saveUserEdit() {
    if (!this.editingUser) return;
    this.applyRoleTenantRules(this.userForm);
    if (this.userForm.role === 'tenant_admin' && this.userForm.tenant_id === 'default') {
      this.showMsg('Tenant admin must be assigned to a tenant', 'error');
      return;
    }

    this.api.updateUser(this.editingUser.id, {
      role: this.userForm.role,
      tenant_id: this.userForm.tenant_id || 'default',
      active: this.userForm.active,
      password: this.userForm.password,
      permissions: this.userForm.permissions,
    }).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.editingUser = null;
          this.loadUsers();
          this.showMsg('User updated', 'success');
        } else {
          this.showMsg(data.message || 'Failed to update user', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.showMsg('Failed to update user', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  setUserActive(user: any, active: boolean) {
    // Optimistically flip the toggle immediately — the UI feels instant.
    const previous = user.active;
    user.active = active;
    this.cdr.detectChanges();

    this.api.setUserStatus(user.id, active).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.showMsg(active ? 'User activated' : 'User deactivated', 'success');
          // Poll with exponential backoff until the ClickHouse mutation
          // is visible in a fresh read, then sync the list.
          this.reloadUsersWithRetry(user.id, active);
        } else {
          // Server rejected the action — revert the optimistic change.
          user.active = previous;
          this.showMsg(data.message || 'Failed to update user status', 'error');
          this.cdr.detectChanges();
        }
      },
      error: () => {
        // Network error — revert so the UI stays consistent with server state.
        user.active = previous;
        this.showMsg('Failed to update user status', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  onTenantNameChange() {
    this.newTenant.id = this.slugifyTenant(this.newTenant.name);
  }

  onTenantIdChange() {
    this.newTenant.id = this.slugifyTenant(this.newTenant.id);
  }

  addTenant() {
    if (!this.newTenant.name) {
      this.tenantMsg = 'Tenant name required';
      return;
    }
    if (!this.newTenant.id) {
      this.tenantMsg = 'Tenant ID required';
      return;
    }
    if (this.tenantIdExists(this.newTenant.id)) {
      this.tenantMsg = 'Tenant ID already exists';
      return;
    }

    this.savingTenant = true;
    this.api.createTenant(this.newTenant).subscribe({
      next: (data: any) => {
        this.savingTenant = false;
        if (data.status === 'ok') {
          this.showAddTenant = false;
          this.newTenant = { name: '', id: '' };
          this.tenantMsg = '';
          this.loadTenants();
          this.showMsg('Tenant created', 'success');
        } else {
          this.tenantMsg = data.message;
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.savingTenant = false;
        this.tenantMsg = 'Failed to create tenant';
        this.cdr.detectChanges();
      },
    });
  }

  openEditTenant(tenant: any) {
    this.editingTenant = tenant;
    this.tenantForm = {
      name: tenant.name,
      active: tenant.active,
    };
  }

  closeEditTenant() {
    this.editingTenant = null;
  }

  saveTenantEdit() {
    if (!this.editingTenant) return;
    if (!this.tenantForm.name.trim()) {
      this.showMsg('Tenant name required', 'error');
      return;
    }

    this.api.updateTenant(this.editingTenant.id, this.tenantForm).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.editingTenant = null;
          this.loadTenants();
          this.showMsg('Tenant updated', 'success');
        } else {
          this.showMsg(data.message || 'Failed to update tenant', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.showMsg('Failed to update tenant', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  setTenantActive(tenant: any, active: boolean) {
    // Optimistically flip the toggle immediately — the UI feels instant.
    const previous = tenant.active;
    tenant.active = active;
    this.cdr.detectChanges();

    this.api.setTenantStatus(tenant.id, active).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.showMsg(active ? 'Tenant activated' : 'Tenant deactivated', 'success');
          // Poll with exponential backoff until the ClickHouse mutation
          // is visible in a fresh read, then sync the list.
          this.reloadTenantsWithRetry(tenant.id, active);
        } else {
          // Server rejected the action — revert the optimistic change.
          tenant.active = previous;
          this.showMsg(data.message || 'Failed to update tenant status', 'error');
          this.cdr.detectChanges();
        }
      },
      error: () => {
        // Network error — revert so the UI stays consistent with server state.
        tenant.active = previous;
        this.showMsg('Failed to update tenant status', 'error');
        this.cdr.detectChanges();
      },
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

  loadEngines() {
    this.loadingEngines = true;
    this.api.getEngines().subscribe({
      next: (data: any) => {
        this.engines = data.engines || [];
        this.loadingEngines = false;
        this.lastEngineRefresh = new Date();
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingEngines = false;
        this.showMsg('Failed to load engines', 'error');
        this.cdr.detectChanges();
      },
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
      },
    });
  }

  requestStopEngine(engine: string) {
    this.pendingStopEngine = engine;
  }

  cancelStopEngine() {
    this.pendingStopEngine = '';
  }

  confirmStopEngine() {
    if (!this.pendingStopEngine) return;
    const engine = this.pendingStopEngine;
    this.api.scaleEngines('down', engine).subscribe({
      next: (data: any) => {
        this.pendingStopEngine = '';
        this.showMsg(data.message, 'success');
        setTimeout(() => this.loadEngines(), 2000);
      },
      error: (err: any) => {
        this.showMsg(err.error?.message || 'Failed to scale down', 'error');
      },
    });
  }

  tenantUserCount(tenantId: string) {
    return this.users.filter(user => user.tenant_id === tenantId).length;
  }

  tenantAdminCount(tenantId: string) {
    return this.tenantAdmins.filter(user => user.tenant_id === tenantId).length;
  }

  blockedUserCount(tenantId: string) {
    return this.isTenantInactive(tenantId)
      ? this.users.filter(user => user.tenant_id === tenantId && user.active !== false).length
      : 0;
  }

  tenantName(tenantId: string) {
    return this.tenants.find(tenant => tenant.id === tenantId)?.name || tenantId;
  }

  isTenantInactive(tenantId: string) {
    return this.tenants.find(tenant => tenant.id === tenantId)?.active === false;
  }

  userStatusLabel(user: any) {
    if (user.active === false) return 'Disabled';
    if (this.isTenantInactive(user.tenant_id)) return 'Blocked by tenant';
    return 'Active';
  }

  userStatusClass(user: any) {
    return user.active === false || this.isTenantInactive(user.tenant_id)
      ? 'inactive'
      : 'active';
  }

  tenantIdExists(id: string) {
    return this.tenants.some(tenant => tenant.id === id);
  }

  roleLabel(role: string) {
    return this.roleOptions.find(option => option.value === role)?.label || role;
  }

  onNewUserRoleChange() {
    this.applyRoleTenantRules(this.newUser);
  }

  onEditUserRoleChange() {
    this.applyRoleTenantRules(this.userForm);
    this.userForm.permissions = this.defaultPermissionsFor(this.userForm.role);
  }

  private defaultPermissionsFor(role: string) {
    switch (role) {
      case 'tenant_admin':
        return 'dashboard,alerts,logs,live,rules,soar,network-map,intel,health,users';
      case 'admin':
        return 'dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,users,setup';
      case 'default_user':
        return 'dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,setup';
      case 'senior_analyst':
        return 'dashboard,alerts,logs,live,rules,soar,network-map,intel,health';
      case 'analyst':
        return 'dashboard,alerts,logs,live,network-map,intel,health';
      default:
        return 'dashboard,alerts,health';
    }
  }

  private applyRoleTenantRules(user: { role: string; tenant_id: string }) {
    if (user.role === 'default_user') {
      user.tenant_id = 'default';
    } else if (user.role !== 'tenant_admin' && !user.tenant_id) {
      user.tenant_id = 'default';
    } else if (user.role === 'tenant_admin' && user.tenant_id === 'default') {
      user.tenant_id = '';
    }
  }

  private slugifyTenant(value: string) {
    return value
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }

  // ── Session expiry ──────────────────────────────────────────────────────────

  /**
   * Polls once per minute to warn the user before their JWT expires.
   * Shows a persistent banner at 5 minutes, auto-logs out at 0.
   */
  private startSessionExpiryCheck(): void {
    const check = () => {
      const msLeft = this.auth.getTokenExpiresInMs();
      if (msLeft <= 0) {
        // Token has expired — force re-login immediately.
        this.auth.logout();
        return;
      }
      if (msLeft <= 5 * 60 * 1000) {
        const minsLeft = Math.ceil(msLeft / 60_000);
        this.sessionExpiryWarning =
          `Your session expires in ${minsLeft} minute${minsLeft !== 1 ? 's' : ''}. ` +
          `Please re-login to avoid interruption.`;
      } else {
        this.sessionExpiryWarning = '';
      }
      this.cdr.detectChanges();
    };

    check(); // Run immediately on init
    this.sessionCheckInterval = setInterval(check, 60_000);
  }

  // ── ClickHouse mutation polling ─────────────────────────────────────────────

  /**
   * After a user active-status mutation, polls the server with exponential
   * backoff until the new value is confirmed, then updates the local list.
   * This prevents stale FINAL reads from overwriting the optimistic UI state.
   *
   * Delays: 1 s → 2 s → 4 s (max 3 attempts = 7 s total window).
   */
  private reloadUsersWithRetry(userId: string, expectedActive: boolean, attempt = 0): void {
    const delays = [1000, 2000, 4000];
    const delay  = delays[attempt] ?? delays[delays.length - 1];

    setTimeout(() => {
      this.api.getUsers().subscribe({
        next: (data: any) => {
          const fresh: any[] = data.users || [];
          const target = fresh.find((u: any) => u.id === userId);

          if (target && target.active !== expectedActive && attempt < delays.length - 1) {
            // Mutation not yet visible — retry with next backoff tier.
            this.reloadUsersWithRetry(userId, expectedActive, attempt + 1);
          } else {
            // Either matched or we've exhausted retries — sync the list.
            this.users = fresh;
            this.cdr.detectChanges();
          }
        },
        error: () => {
          // Silent — the optimistic value stays; the user sees a consistent UI.
        },
      });
    }, delay);
  }

  /**
   * Same pattern as reloadUsersWithRetry but for the tenant list.
   */
  private reloadTenantsWithRetry(tenantId: string, expectedActive: boolean, attempt = 0): void {
    const delays = [1000, 2000, 4000];
    const delay  = delays[attempt] ?? delays[delays.length - 1];

    setTimeout(() => {
      this.api.getTenants().subscribe({
        next: (data: any) => {
          const fresh: any[] = data.tenants || [];
          const target = fresh.find((t: any) => t.id === tenantId);

          if (target && target.active !== expectedActive && attempt < delays.length - 1) {
            this.reloadTenantsWithRetry(tenantId, expectedActive, attempt + 1);
          } else {
            this.tenants = fresh;
            this.cdr.detectChanges();
          }
        },
        error: () => {
          // Silent — the optimistic value stays.
        },
      });
    }, delay);
  }
}
