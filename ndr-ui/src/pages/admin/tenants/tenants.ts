import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Edit, Plus, RefreshCw, Search, X,
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';

@Component({
  selector: 'app-tenants',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './tenants.html',
  styleUrl: './tenants.css',
})
export class Tenants implements OnInit {
  EditIcon    = Edit;
  PlusIcon    = Plus;
  RefreshIcon = RefreshCw;
  SearchIcon  = Search;
  XIcon       = X;

  currentUser: any = {};

  tenants: any[]     = [];
  users: any[]       = [];
  loadingTenants     = false;
  showAddTenant      = false;
  tenantSearch       = '';
  newTenant          = { name: '', id: '' };
  savingTenant       = false;
  tenantMsg          = '';
  editingTenant: any = null;
  tenantForm         = { name: '', active: true };

  msg     = '';
  msgType = '';

  constructor(
    private api: Api,
    private auth: AuthService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit() {
    this.currentUser = this.auth.getUser();
    this.loadTenants();
    this.loadUsers();
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

  loadUsers() {
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.users = data.users || [];
        this.cdr.detectChanges();
      },
      error: () => {},
    });
  }

  get filteredTenants() {
    const query = this.tenantSearch.trim().toLowerCase();
    return this.tenants.filter(t =>
      !query || t.name?.toLowerCase().includes(query) || t.id?.toLowerCase().includes(query)
    );
  }

  get tenantAdmins() {
    return this.users.filter(u => u.role === 'tenant_admin');
  }

  tenantUserCount(tenantId: string) {
    return this.users.filter(u => u.tenant_id === tenantId).length;
  }

  tenantAdminCount(tenantId: string) {
    return this.tenantAdmins.filter(u => u.tenant_id === tenantId).length;
  }

  tenantIdExists(id: string) {
    return this.tenants.some(t => t.id === id);
  }

  get canCreateTenant() {
    return !!this.newTenant.name.trim() && !!this.newTenant.id.trim() && !this.tenantIdExists(this.newTenant.id);
  }

  onTenantNameChange() { this.newTenant.id = this.slugifyTenant(this.newTenant.name); }
  onTenantIdChange()   { this.newTenant.id = this.slugifyTenant(this.newTenant.id); }

  private slugifyTenant(value: string) {
    return value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  }

  addTenant() {
    if (!this.newTenant.name) { this.tenantMsg = 'Tenant name required'; return; }
    if (!this.newTenant.id)   { this.tenantMsg = 'Tenant ID required'; return; }
    if (this.tenantIdExists(this.newTenant.id)) { this.tenantMsg = 'Tenant ID already exists'; return; }

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
    this.tenantForm = { name: tenant.name, active: tenant.active };
  }

  closeEditTenant() { this.editingTenant = null; }

  saveTenantEdit() {
    if (!this.editingTenant) return;
    if (!this.tenantForm.name.trim()) { this.showMsg('Tenant name required', 'error'); return; }

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
      error: () => { this.showMsg('Failed to update tenant', 'error'); this.cdr.detectChanges(); },
    });
  }

  setTenantActive(tenant: any, active: boolean) {
    const previous = tenant.active;
    tenant.active = active;
    this.cdr.detectChanges();

    this.api.setTenantStatus(tenant.id, active).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.showMsg(active ? 'Tenant activated' : 'Tenant deactivated', 'success');
          this.reloadTenantsWithRetry(tenant.id, active);
        } else {
          tenant.active = previous;
          this.showMsg(data.message || 'Failed to update tenant status', 'error');
          this.cdr.detectChanges();
        }
      },
      error: () => {
        tenant.active = previous;
        this.showMsg('Failed to update tenant status', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  toggleTenantAI(tenant: any, enabled: boolean) {
    const previous = tenant.ai_enabled;
    tenant.ai_enabled = enabled;
    this.cdr.detectChanges();
    this.api.setTenantAiEnabled(tenant.id, enabled).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.showMsg(`AI features ${enabled ? 'enabled' : 'disabled'} for ${tenant.name}`, 'success');
        } else {
          tenant.ai_enabled = previous;
          this.showMsg(data.message || 'Failed to update AI setting', 'error');
          this.cdr.detectChanges();
        }
      },
      error: () => {
        tenant.ai_enabled = previous;
        this.showMsg('Failed to update AI setting', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  private reloadTenantsWithRetry(tenantId: string, expectedActive: boolean, attempt = 0): void {
    const delays = [1000, 2000, 4000];
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
        error: () => {},
      });
    }, delays[attempt] ?? delays[delays.length - 1]);
  }

  showMsg(msg: string, type: string) {
    this.msg = msg;
    this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
