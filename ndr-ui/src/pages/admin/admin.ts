import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Building2,
  CircleCheck,
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
export class Admin implements OnInit {
  BuildingIcon = Building2;
  CheckIcon = CircleCheck;
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
  newUser = {
    username: '',
    password: '',
    role: 'tenant_admin',
    tenant_id: '',
  };
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

  engines: any[] = [];
  loadingEngines = false;
  scaling = false;
  lastEngineRefresh: Date | null = null;
  pendingStopEngine = '';

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

  get tenantAdmins() {
    return this.users.filter(user => user.role === 'tenant_admin');
  }

  get filteredTenantAdmins() {
    const query = this.userSearch.trim().toLowerCase();
    return this.tenantAdmins.filter(user => {
      const matchesTenant = this.selectedTenant === 'all' || user.tenant_id === this.selectedTenant;
      const matchesQuery =
        !query ||
        user.username?.toLowerCase().includes(query) ||
        user.tenant_id?.toLowerCase().includes(query);
      return matchesTenant && matchesQuery;
    });
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
    if (!this.newUser.tenant_id || this.newUser.tenant_id === 'default') {
      this.showMsg('Select a tenant for the tenant admin', 'error');
      return;
    }

    this.savingUser = true;
    this.api
      .createUser({
        ...this.newUser,
        role: 'tenant_admin',
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

  tenantName(tenantId: string) {
    return this.tenants.find(tenant => tenant.id === tenantId)?.name || tenantId;
  }

  tenantIdExists(id: string) {
    return this.tenants.some(tenant => tenant.id === id);
  }

  private slugifyTenant(value: string) {
    return value
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }
}
