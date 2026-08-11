import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Edit, Plus, RefreshCw, Search, X, KeyRound, Copy,
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
  KeyIcon     = KeyRound;
  CopyIcon    = Copy;

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

  // Feature management
  featureTenant: any  = null;
  featureForm         = { ndr: true, ai: true, soar: false };
  savingFeatures      = false;

  // License generation
  licenseTenant: any  = null;
  licenseForm         = { expires_days: 365, max_sensors: 10, admin_user: '', admin_pass: '' };
  generatedToken      = '';
  generatingLicense   = false;
  tokenCopied         = false;
  licensePublicKey    = '';
  installCopied       = false;
  issuedLicenses: any[] = [];
  loadingLicenses     = false;

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

  openFeatures(tenant: any) {
    this.featureTenant = tenant;
    const feats: string[] = tenant.features ?? ['ndr', 'ai'];
    this.featureForm = {
      ndr:  feats.includes('ndr'),
      ai:   feats.includes('ai'),
      soar: feats.includes('soar'),
    };
    this.cdr.detectChanges();
  }

  closeFeatures() { this.featureTenant = null; this.cdr.detectChanges(); }

  saveFeatures() {
    if (!this.featureTenant) return;
    const features: string[] = [];
    if (this.featureForm.ndr)  features.push('ndr');
    if (this.featureForm.ai)   features.push('ai');
    if (this.featureForm.soar) features.push('soar');
    this.savingFeatures = true;
    this.api.setTenantFeatures(this.featureTenant.id, features).subscribe({
      next: () => {
        this.featureTenant.features = features;
        this.savingFeatures = false;
        this.closeFeatures();
        this.showMsg('Features updated', 'success');
        this.cdr.detectChanges();
      },
      error: () => {
        this.savingFeatures = false;
        this.showMsg('Failed to save features', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  openLicense(tenant: any) {
    this.licenseTenant   = tenant;
    this.generatedToken  = '';
    this.tokenCopied     = false;
    this.licenseForm     = { expires_days: 365, max_sensors: 10, admin_user: '', admin_pass: '' };
    this.issuedLicenses  = [];
    this.loadingLicenses = true;
    this.cdr.detectChanges();
    // Load public key + existing licenses in parallel
    this.api.getLicensePublicKey().subscribe({
      next: (r: any) => { this.licensePublicKey = r.public_key ?? ''; this.cdr.detectChanges(); },
      error: () => {},
    });
    this.api.getLicenses(tenant.id).subscribe({
      next: (r: any) => {
        this.issuedLicenses  = r.licenses ?? [];
        this.loadingLicenses = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loadingLicenses = false; this.cdr.detectChanges(); },
    });
  }

  closeLicense() { this.licenseTenant = null; this.generatedToken = ''; this.cdr.detectChanges(); }

  generateLicense() {
    if (!this.licenseTenant) return;
    const features: string[] = this.licenseTenant.features ?? ['ndr', 'ai'];
    this.generatingLicense = true;
    this.api.generateLicense({
      tenant_id:    this.licenseTenant.id,
      tenant_name:  this.licenseTenant.name,
      features,
      max_sensors:  this.licenseForm.max_sensors,
      expires_days: this.licenseForm.expires_days,
    }).subscribe({
      next: (data: any) => {
        this.generatedToken    = data.token ?? '';
        this.generatingLicense = false;
        this.installCopied     = false;
        // Reload license list to include the one just generated
        this.api.getLicenses(this.licenseTenant?.id).subscribe({
          next: (r: any) => { this.issuedLicenses = r.licenses ?? []; this.cdr.detectChanges(); },
          error: () => {},
        });
        this.cdr.detectChanges();
      },
      error: () => {
        this.generatingLicense = false;
        this.showMsg('Failed to generate license', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  copyInstallPackage(token?: string, license?: any) {
    const useToken = token ?? this.generatedToken;
    const useExpires = license?.expires_at
      ? `until ${license.expires_at.slice(0, 10)}`
      : `${this.licenseForm.expires_days} days`;
    const useMaxSensors = license?.max_sensors ?? this.licenseForm.max_sensors;
    const useFeatures = license?.features ?? this.licenseTenant?.features ?? ['ndr', 'ai'];
    const useAdminUser = this.licenseForm.admin_user.trim();
    const useAdminPass = this.licenseForm.admin_pass;
    const installCmd = `bash <(curl -fsSL https://raw.githubusercontent.com/jithinjoseph-workspace/NDR-Demo/arkime/install-customer.sh)`;
    const credLines = useAdminUser
      ? [`   Tenant admin username : ${useAdminUser}`, `   Tenant admin password : ${useAdminPass || '(set separately)'}`]
      : [`   Tenant admin username : (set TENANT_ADMIN_USER in .env)`, `   Tenant admin password : (set TENANT_ADMIN_PASS in .env)`];
    const instructions = [
      `=== ProVigilAI Install Package for ${this.licenseTenant?.name} ===`,
      ``,
      `1. Run on the client's Ubuntu server:`,
      `   ${installCmd}`,
      ``,
      `2. When prompted, enter:`,
      `   License public key    : (paste the key shown in the portal)`,
      `   License token         : ${useToken}`,
      ...credLines,
      ``,
      `Features : ${useFeatures.join(', ')}`,
      `Expires  : ${useExpires}`,
      `Sensors  : up to ${useMaxSensors}`,
    ].join('\n');

    navigator.clipboard.writeText(instructions).then(() => {
      this.installCopied = true;
      setTimeout(() => { this.installCopied = false; this.cdr.detectChanges(); }, 2500);
      this.cdr.detectChanges();
    });
  }

  copyToken() {
    if (!this.generatedToken) return;
    navigator.clipboard.writeText(this.generatedToken).then(() => {
      this.tokenCopied = true;
      setTimeout(() => { this.tokenCopied = false; this.cdr.detectChanges(); }, 2000);
      this.cdr.detectChanges();
    });
  }

  showMsg(msg: string, type: string) {
    this.msg = msg;
    this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
