import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Building2,
  ChevronDown,
  ChevronRight,
  CircleCheck,
  Copy,
  Download,
  Edit,
  Gauge,
  KeyRound,
  Megaphone,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
  X,
  Bot,
  Eye,
  EyeOff,
  Zap,
  LoaderCircle,
  AlertTriangle,
  Activity,
  Save,
  LayoutDashboard,
  Cpu,
  MemoryStick
} from 'lucide-angular';
import * as d3 from 'd3';
import { Announcement, Api, SensorKey } from '../../services/api/api';
import { AuthService } from '../../services/auth/auth';
import { Router, ActivatedRoute } from '@angular/router';

type AnnouncementType = 'info' | 'maintenance' | 'update' | 'critical';
type AnnouncementAudience = 'all' | 'tenant_admins' | 'tenant';

interface AnnouncementDraft {
  title: string;
  message: string;
  type: AnnouncementType;
  audience: AnnouncementAudience;
  tenant_id: string;
  starts_at: string;
  ends_at: string;
  active: boolean;
}

interface AiProvider {
  name: string;
  provider_type: string;
  model: string;
  base_url: string;
  endpoint_path: string;
  msg_format: string;
  use_case: string;
  priority: number;
  enabled: boolean;
  key_set: boolean;
}

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
  CopyIcon = Copy;
  EditIcon = Edit;
  GaugeIcon = Gauge;
  KeyIcon = KeyRound;
  AnnouncementIcon = Megaphone;
  PlusIcon = Plus;
  RefreshIcon = RefreshCw;
  SearchIcon = Search;
  ServerIcon = Server;
  ShieldIcon = ShieldCheck;
  TrashIcon = Trash2;
  UserPlusIcon = UserPlus;
  UsersIcon = Users;
  XIcon = X;
  ChevronDownIcon = ChevronDown;
  ChevronRightIcon = ChevronRight;
  ActivityIcon = Activity;
  BotIcon = Bot;
  EyeIcon = Eye;
  EyeOffIcon = EyeOff;
  TestIcon = Zap;
  LoadingIcon = LoaderCircle;
  SaveIcon = Save;
  LayoutDashboardIcon = LayoutDashboard;
  CpuIcon = Cpu;
  MemoryStickIcon = MemoryStick;
  DownloadIcon = Download;

  // Community rules sync state
  syncingRules = false;
  syncMessage = '';
  syncError = false;

  syncCommunityRules() {
    this.syncingRules = true;
    this.syncMessage = '';
    this.syncError = false;
    this.api.syncCommunityRules().subscribe({
      next: (res: any) => {
        this.syncingRules = false;
        this.syncMessage = res.message || `${res.new_rules ?? 0} community rules synced from SigmaHQ`;
        this.syncError = false;
      },
      error: (err: any) => {
        this.syncingRules = false;
        this.syncMessage = err?.error?.error || 'Sync failed';
        this.syncError = true;
      }
    });
  }

  // AI Providers state
  providers: AiProvider[] = [];
  loadingProviders = false;
  savingProvider = false;
  providerMessage = '';
  providerError = '';
  testProviderResult = '';
  showAddProviderForm = false;
  testingProvider = '';
  showProviderKey = false;
  isEditingProvider = false;
  newProvider = {
    name: '', provider_type: 'custom', api_key: '', model: '',
    base_url: '', endpoint_path: '/v1/chat/completions',
    msg_format: 'openai', use_case: 'all', priority: 10, enabled: true,
  };
  providerTypeOptions = [
    { value: 'custom', label: 'Custom / OpenAI-compatible' },
    { value: 'openai', label: 'OpenAI' },
    { value: 'anthropic', label: 'Anthropic' },
  ];
  useCaseOptions = [
    { value: 'all', label: 'All (chat + threat analysis)' },
    { value: 'chat', label: 'ARIA chat only' },
    { value: 'threat', label: 'Threat analysis only' },
  ];

  activeTab = 'overview';
  telemetryData: any = null;
  private telemetryInterval: ReturnType<typeof setInterval> | null = null;
  
  overviewTelemetryHistory: {time: Date, cpu: number, mem: number}[] = [];
  private overviewTelemetryPollTimer: any = null;

  // Trusted cloud settings
  trustedCloud: { keywords: string[], domains: string[], suggestions: { org: string, hits: number }[] } =
    { keywords: [], domains: [], suggestions: [] };
  newKeyword = '';
  newDomain = '';
  trustedCloudSaving = false;
  trustedCloudSaved = false;
  loadingTrustedCloud = false;

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
  readonly usernamePattern = /^[A-Za-z0-9._-]+$/;
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

  sensorKeys: SensorKey[] = [];
  loadingSensorKeys = false;
  creatingSensorKey = false;
  newSensorKey = {
    tenant_id: '',
    name: '',
  };
  createdSensorKey: SensorKey | null = null;
  showSensorKeyModal = false;
  installCommand = '';

  engines: any[] = [];
  loadingEngines = false;
  scaling = false;
  lastEngineRefresh: Date | null = null;
  pendingStopEngine = '';

  kafkaData: any = null;
  kafkaLoading = false;
  private kafkaInterval: any = null;

  showAddAnnouncement = false;
  pendingDeleteAnnouncement: Announcement | null = null;
  loadingAnnouncements = false;
  savingAnnouncement = false;
  announcementSearch = '';
  announcementAudience = 'all_audiences';
  announcements: Announcement[] = [];

  // Friendly date/time picker state
  announcementStartDate = '';
  announcementStartTime = '';
  announcementEndDate = '';
  announcementEndTime = '';

  /** 30-minute time slots for the time dropdown */
  readonly timeSlots = (() => {
    const slots: { value: string; label: string }[] = [];
    for (let h = 0; h < 24; h++) {
      for (const m of [0, 30]) {
        const hh = String(h).padStart(2, '0');
        const mm = String(m).padStart(2, '0');
        const suffix = h < 12 ? 'AM' : 'PM';
        const displayH = h === 0 ? 12 : h > 12 ? h - 12 : h;
        slots.push({ value: `${hh}:${mm}`, label: `${displayH}:${mm} ${suffix}` });
      }
    }
    return slots;
  })();

  /** Today's date as a yyyy-mm-dd string — used as the min for the start date picker. */
  get todayDate(): string {
    return new Date().toISOString().split('T')[0];
  }

  /**
   * Time slots available for the start time picker.
   * When today is selected, past half-hour slots are removed so the admin
   * cannot pick a start time that has already elapsed.
   */
  get filteredStartTimeSlots(): { value: string; label: string }[] {
    if (this.announcementStartDate !== this.todayDate) return this.timeSlots;
    const now = new Date();
    const currentMinutes = now.getHours() * 60 + now.getMinutes();
    return this.timeSlots.filter(t => {
      const [h, m] = t.value.split(':').map(Number);
      return (h * 60 + m) > currentMinutes;
    });
  }

  /**
   * Time slots available for the end time picker.
   * When the end date equals the start date, slots at or before the chosen
   * start time are removed so the end cannot precede the start.
   */
  get filteredEndTimeSlots(): { value: string; label: string }[] {
    if (
      this.announcementEndDate &&
      this.announcementStartDate &&
      this.announcementEndDate === this.announcementStartDate &&
      this.announcementStartTime
    ) {
      const [sh, sm] = this.announcementStartTime.split(':').map(Number);
      const startMinutes = sh * 60 + sm;
      return this.timeSlots.filter(t => {
        const [h, m] = t.value.split(':').map(Number);
        return (h * 60 + m) > startMinutes;
      });
    }
    return this.timeSlots;
  }

  newAnnouncement: AnnouncementDraft = {
    title: '',
    message: '',
    type: 'info',
    audience: 'tenant_admins',
    tenant_id: '',
    starts_at: '',
    ends_at: '',
    active: true,
  };



  currentUser: any = {};
  /** Non-empty when the session is about to expire or has expired. */
  sessionExpiryWarning = '';
  private sessionCheckInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    private api: Api,
    private auth: AuthService,
    private router: Router,
    private route: ActivatedRoute,
    private cdr: ChangeDetectorRef
  ) { }

  ngOnInit() {
    this.currentUser = this.auth.getUser();
    if (!this.auth.isAdmin()) {
      this.router.navigate(['/dashboard']);
      return;
    }
    this.route.queryParams.subscribe(params => {
      if (params['tab']) {
        this.switchTab(params['tab']);
      }
    });
    this.loadUsers();
    this.loadTenants();
    this.loadSensorKeys();
    this.loadEngines();
    this.loadAnnouncements();
    this.loadTrustedCloud();
    this.startSessionExpiryCheck();
  }

  ngAfterViewInit() {
    if (this.activeTab === 'overview') {
      // Need a slight delay to ensure D3 containers have actual dimensions
      setTimeout(() => {
        this.renderD3Charts();
        this.setupResizeObserver();
        this.startOverviewTelemetryPolling();
      }, 150);
    }
  }

  private resizeObserver: any = null;
  private resizeTimeout: any = null;

  ngOnDestroy(): void {
    // Always clear the interval when the component is torn down
    // to avoid a dangling callback and potential memory leak.
    if (this.overviewTelemetryPollTimer) clearInterval(this.overviewTelemetryPollTimer);
    if (this.sessionCheckInterval !== null) {
      clearInterval(this.sessionCheckInterval);
    }
    if (this.telemetryInterval !== null) {
      clearInterval(this.telemetryInterval);
    }
    if (this.kafkaInterval !== null) {
      clearInterval(this.kafkaInterval);
    }
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }
  }

  private setupResizeObserver() {
    const grid = document.querySelector('.overview-grid');
    if (grid && !this.resizeObserver) {
      this.resizeObserver = new ResizeObserver(() => {
        if (this.resizeTimeout) clearTimeout(this.resizeTimeout);
        this.resizeTimeout = setTimeout(() => this.renderD3Charts(), 100);
      });
      this.resizeObserver.observe(grid);
    }
  }

  switchTab(tab: string) {
    this.activeTab = tab;
    if (tab === 'telemetry') {
      this.loadTelemetry();
      if (!this.telemetryInterval) {
        this.telemetryInterval = setInterval(() => this.loadTelemetry(), 5000);
      }
    } else if (tab === 'overview') {
      setTimeout(() => {
        this.renderD3Charts();
        this.setupResizeObserver();
        this.startOverviewTelemetryPolling();
      }, 50);
    } else {
      this.stopOverviewTelemetryPolling();
      if (this.telemetryInterval !== null) {
        clearInterval(this.telemetryInterval);
        this.telemetryInterval = null;
      }
      if (this.resizeObserver) {
        this.resizeObserver.disconnect();
        this.resizeObserver = null;
      }
    }
    if (tab === 'engines') {
      this.loadKafkaStatus();
      if (!this.kafkaInterval) {
        this.kafkaInterval = setInterval(() => this.loadKafkaStatus(), 10000);
      }
    } else {
      if (this.kafkaInterval !== null) {
        clearInterval(this.kafkaInterval);
        this.kafkaInterval = null;
      }
    }
    if (tab === 'trusted-cloud') {
      this.loadTrustedCloud();
    }
    if (tab === 'ai-providers') {
      this.loadProviders();
    }
  }

  startOverviewTelemetryPolling() {
    if (this.overviewTelemetryPollTimer) return;
    this.pollOverviewTelemetry();
    this.overviewTelemetryPollTimer = setInterval(() => this.pollOverviewTelemetry(), 3000);
  }

  stopOverviewTelemetryPolling() {
    if (this.overviewTelemetryPollTimer) {
      clearInterval(this.overviewTelemetryPollTimer);
      this.overviewTelemetryPollTimer = null;
    }
  }

  pollOverviewTelemetry() {
    if (this.activeTab !== 'overview') {
      this.stopOverviewTelemetryPolling();
      return;
    }
    this.api.getPlatformTelemetry().subscribe({
      next: (data: any) => {
        const now = new Date();
        this.overviewTelemetryHistory.push({
          time: now,
          cpu: data.cpu_usage_percent || 0,
          mem: data.memory_percent || 0
        });
        if (this.overviewTelemetryHistory.length > 20) {
          this.overviewTelemetryHistory.shift();
        }
        this.renderResourceUtilizationArea();
      }
    });
  }

  // ── Trusted cloud ────────────────────────────────────────────────────────

  loadTrustedCloud() {
    this.loadingTrustedCloud = true;
    this.api.getTrustedCloudSettings().subscribe({
      next: (data: any) => {
        this.trustedCloud = data;
        this.loadingTrustedCloud = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loadingTrustedCloud = false; },
    });
  }

  addKeyword() {
    const kw = this.newKeyword.trim().toUpperCase();
    if (kw && !this.trustedCloud.keywords.includes(kw)) {
      this.trustedCloud.keywords.push(kw);
    }
    this.newKeyword = '';
  }

  removeKeyword(kw: string) {
    this.trustedCloud.keywords = this.trustedCloud.keywords.filter(k => k !== kw);
  }

  addDomain() {
    const d = this.newDomain.trim().toLowerCase();
    if (d && !this.trustedCloud.domains.includes(d)) {
      this.trustedCloud.domains.push(d);
    }
    this.newDomain = '';
  }

  removeDomain(d: string) {
    this.trustedCloud.domains = this.trustedCloud.domains.filter(x => x !== d);
  }

  saveTrustedCloud() {
    this.trustedCloudSaving = true;
    this.trustedCloudSaved = false;
    this.api.updateTrustedCloudSettings({
      keywords: this.trustedCloud.keywords,
      domains: this.trustedCloud.domains,
    }).subscribe({
      next: () => {
        this.trustedCloudSaving = false;
        this.trustedCloudSaved = true;
        setTimeout(() => { this.trustedCloudSaved = false; }, 3000);
      },
      error: () => { this.trustedCloudSaving = false; },
    });
  }

  approveSuggestion(org: string) {
    this.api.approveTrustedCloudSuggestion(org).subscribe({
      next: () => {
        this.trustedCloud.suggestions = this.trustedCloud.suggestions.filter(s => s.org !== org);
        if (!this.trustedCloud.keywords.includes(org.split(' ')[0])) {
          this.trustedCloud.keywords.push(org.split(' ')[0]);
        }
      },
      error: () => { },
    });
  }

  rejectSuggestion(org: string) {
    this.api.rejectTrustedCloudSuggestion(org).subscribe({
      next: () => {
        this.trustedCloud.suggestions = this.trustedCloud.suggestions.filter(s => s.org !== org);
      },
      error: () => { },
    });
  }

  loadKafkaStatus() {
    this.kafkaLoading = !this.kafkaData;
    this.api.getKafkaStatus().subscribe({
      next: (data: any) => { this.kafkaData = data; this.kafkaLoading = false; },
      error: () => { this.kafkaLoading = false; }
    });
  }

  getEngineForPartition(partition: number): string {
    const c = (this.kafkaData?.consumers || []).find((c: any) => c.partition === partition);
    return c?.engine || '-';
  }

  getLagForPartition(partition: number): number {
    const c = (this.kafkaData?.consumers || []).find((c: any) => c.partition === partition);
    return c?.lag ?? 0;
  }

  loadTelemetry() {
    this.api.getPlatformTelemetry().subscribe({
      next: (data: any) => {
        this.telemetryData = data;
        this.cdr.detectChanges();
      }
    });
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

  /** Tracks which tenant group accordion sections are collapsed. */
  collapsedTenants = new Set<string>();

  /** Groups filteredTenantAdmins by tenant for the accordion view. */
  get usersByTenant(): { tenantId: string; tenantName: string; isActive: boolean; users: any[] }[] {
    const groups = new Map<string, any[]>();
    for (const user of this.filteredTenantAdmins) {
      const tid = user.tenant_id || 'default';
      if (!groups.has(tid)) groups.set(tid, []);
      groups.get(tid)!.push(user);
    }
    return Array.from(groups.entries()).map(([tenantId, users]) => {
      const tenant = this.tenants.find(t => t.id === tenantId);
      return {
        tenantId,
        tenantName: tenant?.name ?? tenantId,
        isActive: tenant?.active ?? true,
        users,
      };
    });
  }

  toggleTenantGroup(tenantId: string) {
    if (this.collapsedTenants.has(tenantId)) {
      this.collapsedTenants.delete(tenantId);
    } else {
      this.collapsedTenants.add(tenantId);
    }
  }

  isGroupCollapsed(tenantId: string): boolean {
    return this.collapsedTenants.has(tenantId);
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

  get activeAnnouncements() {
    return this.announcements.filter(announcement => announcement.active).length;
  }

  get filteredAnnouncements() {
    const query = this.announcementSearch.trim().toLowerCase();
    return this.announcements.filter(announcement => {
      const tenantId = this.announcementTenantId(announcement);
      const matchesAudience =
        this.announcementAudience === 'all_audiences' ||
        announcement.audience === this.announcementAudience ||
        tenantId === this.announcementAudience;
      const matchesQuery =
        !query ||
        announcement.title.toLowerCase().includes(query) ||
        announcement.message.toLowerCase().includes(query) ||
        this.announcementTypeLabel(announcement.type).toLowerCase().includes(query) ||
        this.announcementAudienceLabel(announcement).toLowerCase().includes(query);
      return matchesAudience && matchesQuery;
    });
  }

  get canCreateAnnouncement() {
    const endAfterStart =
      !this.newAnnouncement.ends_at ||
      !this.newAnnouncement.starts_at ||
      this.newAnnouncement.ends_at > this.newAnnouncement.starts_at;
    return (
      !!this.newAnnouncement.title.trim() &&
      !!this.newAnnouncement.message.trim() &&
      (this.newAnnouncement.audience !== 'tenant' || !!this.newAnnouncement.tenant_id) &&
      endAfterStart
    );
  }

  get endBeforeStartError(): boolean {
    return (
      !!this.newAnnouncement.ends_at &&
      !!this.newAnnouncement.starts_at &&
      this.newAnnouncement.ends_at <= this.newAnnouncement.starts_at
    );
  }

  get canCreateTenant() {
    return (
      !!this.newTenant.name.trim() &&
      !!this.newTenant.id.trim() &&
      !this.tenantIdExists(this.newTenant.id)
    );
  }

  get newUserUsernameError() {
    return this.validateUsername(this.newUser.username, true);
  }

  get newUserPasswordErrors() {
    return this.validatePassword(this.newUser.password, this.newUser.username, true);
  }

  get newUserRoleError() {
    return this.validateRole(this.newUser.role);
  }

  get newUserTenantError() {
    return this.validateUserTenant(this.newUser.role, this.newUser.tenant_id);
  }

  get canCreateUser() {
    return (
      !this.newUserUsernameError &&
      this.newUserPasswordErrors.length === 0 &&
      !this.newUserRoleError &&
      !this.newUserTenantError
    );
  }

  get editUserPasswordErrors() {
    return this.validatePassword(this.userForm.password, this.editingUser?.username || '', false);
  }

  get editUserRoleError() {
    return this.validateRole(this.userForm.role);
  }

  get editUserTenantError() {
    return this.validateUserTenant(this.userForm.role, this.userForm.tenant_id);
  }

  get canSaveUserEdit() {
    return (
      !!this.editingUser &&
      !this.editUserRoleError &&
      !this.editUserTenantError &&
      this.editUserPasswordErrors.length === 0 &&
      !this.isCurrentSuperAdmin(this.editingUser)
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
    this.applyRoleTenantRules(this.newUser);
    if (!this.canCreateUser) {
      this.showMsg(this.firstNewUserValidationError(), 'error');
      return;
    }
    if (!this.newUser.username || !this.newUser.password) {
      this.showMsg('Username and password required', 'error');
      return;
    }
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
    if (this.isCurrentSuperAdmin(user)) {
      this.showMsg('Current super admin cannot be deleted', 'error');
      return;
    }
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
    if (this.isCurrentSuperAdmin(user)) {
      this.showMsg('Current super admin cannot be edited', 'error');
      return;
    }
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
    if (this.isCurrentSuperAdmin(this.editingUser)) {
      this.showMsg('Current super admin cannot be edited', 'error');
      return;
    }
    this.applyRoleTenantRules(this.userForm);
    if (!this.canSaveUserEdit) {
      this.showMsg(this.firstEditUserValidationError(), 'error');
      return;
    }
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
    if (this.isCurrentSuperAdmin(user)) {
      this.showMsg('Current super admin cannot be deactivated', 'error');
      return;
    }
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

  loadSensorKeys() {
    this.loadingSensorKeys = true;
    this.api.getSensorKeys().subscribe({
      next: (keys: SensorKey[]) => {
        this.sensorKeys = keys;
        this.loadingSensorKeys = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingSensorKeys = false;
        this.showMsg('Failed to load sensor keys', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  createSensorKey() {
    const tenantId = this.newSensorKey.tenant_id;
    const name = this.newSensorKey.name.trim();
    if (!tenantId || !name) {
      this.showMsg('Tenant and sensor name are required', 'error');
      return;
    }

    this.creatingSensorKey = true;
    this.api.createSensorKey(tenantId, name).subscribe({
      next: (data: any) => {
        this.creatingSensorKey = false;
        if (data.status === 'ok' && data.key) {
          this.createdSensorKey = {
            id: data.id,
            key: data.key,
            key_prefix: data.key.slice(0, 16),
            tenant_id: tenantId,
            name,
            active: true,
            created_at: new Date().toISOString(),
            last_seen: '',
          };
          this.installCommand =
            `sudo bash install-sensor.sh --cloud-url https://your-ndr.com ` +
            `--tenant-id ${tenantId} --api-key ${data.key}`;
          this.showSensorKeyModal = true;
          this.newSensorKey = { tenant_id: '', name: '' };
          this.loadSensorKeys();
        } else {
          this.showMsg(data.message || 'Failed to create sensor key', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.creatingSensorKey = false;
        this.showMsg('Failed to create sensor key', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  revokeSensorKey(key: SensorKey) {
    if (!key.active) return;
    this.api.revokeSensorKey(key.id).subscribe({
      next: (data: any) => {
        if (!data.status || data.status === 'ok') {
          key.active = false;
          this.showMsg('Sensor key revoked', 'success');
          this.loadSensorKeys();
        } else {
          this.showMsg(data.message || 'Failed to revoke sensor key', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.showMsg('Failed to revoke sensor key', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  reactivateSensorKey(key: SensorKey) {
    if (key.active) return;
    this.api.reactivateSensorKey(key.id).subscribe({
      next: (data: any) => {
        if (!data.status || data.status === 'ok') {
          key.active = true;
          this.showMsg('Sensor key reactivated', 'success');
          this.loadSensorKeys();
        } else {
          this.showMsg(data.message || 'Failed to reactivate sensor key', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.showMsg('Failed to reactivate sensor key', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  closeSensorKeyModal() {
    this.showSensorKeyModal = false;
  }

  copyCreatedSensorKey() {
    if (this.createdSensorKey?.key) {
      this.copyText(this.createdSensorKey.key, 'Sensor key copied');
    }
  }

  copyInstallCommand() {
    if (this.installCommand) {
      this.copyText(this.installCommand, 'Install command copied');
    }
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

  loadAnnouncements() {
    this.loadingAnnouncements = true;
    this.api.getAnnouncements().subscribe({
      next: announcements => {
        this.announcements = announcements.map(announcement => this.normalizeAnnouncement(announcement));
        this.loadingAnnouncements = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingAnnouncements = false;
        this.showMsg('Failed to load announcements', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  addAnnouncement() {
    if (!this.canCreateAnnouncement) {
      this.showMsg('Title, message, and audience are required', 'error');
      return;
    }

    this.savingAnnouncement = true;
    this.api.createAnnouncement(this.buildAnnouncementPayload(this.newAnnouncement)).subscribe({
      next: (data: any) => {
        this.savingAnnouncement = false;
        if (data.status === 'ok') {
          this.showAddAnnouncement = false;
          this.resetAnnouncementForm();
          this.loadAnnouncements();
          this.showMsg('Announcement created', 'success');
        } else {
          this.showMsg(data.message || 'Failed to create announcement', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.savingAnnouncement = false;
        this.showMsg('Failed to create announcement', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  toggleAnnouncement(announcement: Announcement) {
    const previous = announcement.active;
    const nextActive = !announcement.active;
    announcement.active = nextActive;
    this.cdr.detectChanges();

    this.api.updateAnnouncement(announcement.id, {
      ...this.buildAnnouncementPayload({
        title: announcement.title,
        message: announcement.message,
        type: announcement.type,
        audience: announcement.audience,
        tenant_id: this.announcementTenantId(announcement),
        starts_at: announcement.starts_at || announcement.start_at || '',
        ends_at: announcement.ends_at || announcement.end_at || '',
        active: nextActive,
      }),
    }).subscribe({
      next: (data: any) => {
        if (data.status === 'ok') {
          this.loadAnnouncements();
          this.showMsg(nextActive ? 'Announcement activated' : 'Announcement deactivated', 'success');
        } else {
          announcement.active = previous;
          this.showMsg(data.message || 'Failed to update announcement', 'error');
          this.cdr.detectChanges();
        }
      },
      error: () => {
        announcement.active = previous;
        this.showMsg('Failed to update announcement', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  requestDeleteAnnouncement(announcement: Announcement) {
    this.pendingDeleteAnnouncement = announcement;
  }

  cancelDeleteAnnouncement() {
    this.pendingDeleteAnnouncement = null;
  }

  confirmDeleteAnnouncement() {
    if (!this.pendingDeleteAnnouncement) return;
    const id = this.pendingDeleteAnnouncement.id;
    this.api.deleteAnnouncement(id).subscribe({
      next: (data: any) => {
        this.pendingDeleteAnnouncement = null;
        if (data.status === 'ok') {
          this.loadAnnouncements();
          this.showMsg('Announcement deleted', 'success');
        } else {
          this.showMsg(data.message || 'Failed to delete announcement', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.showMsg('Failed to delete announcement', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  closeAddAnnouncement() {
    this.showAddAnnouncement = false;
    this.resetAnnouncementForm();
  }

  onAnnouncementAudienceChange() {
    if (this.newAnnouncement.audience !== 'tenant') {
      this.newAnnouncement.tenant_id = '';
    }
  }

  onStartDateTimeChange() {
    this.newAnnouncement.starts_at = this.buildIso(
      this.announcementStartDate, this.announcementStartTime
    );
  }

  onEndDateTimeChange() {
    this.newAnnouncement.ends_at = this.buildIso(
      this.announcementEndDate, this.announcementEndTime
    );
  }

  clearStartDateTime() {
    this.announcementStartDate = '';
    this.announcementStartTime = '';
    this.newAnnouncement.starts_at = '';
  }

  clearEndDateTime() {
    this.announcementEndDate = '';
    this.announcementEndTime = '';
    this.newAnnouncement.ends_at = '';
  }

  private buildIso(date: string, time: string): string {
    if (!date) return '';
    return time ? `${date}T${time}:00` : `${date}T00:00:00`;
  }

  announcementTypeLabel(type: AnnouncementType) {
    switch (type) {
      case 'maintenance':
        return 'Maintenance';
      case 'update':
        return 'Platform Update';
      case 'critical':
        return 'Critical';
      default:
        return 'Information';
    }
  }

  announcementAudienceLabel(announcement: Partial<AnnouncementDraft & Announcement>) {
    if (announcement.audience === 'tenant') {
      return `Tenant: ${this.tenantName(this.announcementTenantId(announcement))}`;
    }
    if (announcement.audience === 'tenant_admins') return 'Tenant admins';
    return 'All users';
  }

  announcementTypeClass(type: AnnouncementType) {
    return `announcement-${type}`;
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

  usernameExists(username: string) {
    const normalized = username.trim().toLowerCase();
    return this.users.some(user => user.username?.trim().toLowerCase() === normalized);
  }

  isCurrentSuperAdmin(user: any) {
    return user?.role === 'super_admin' && user?.username === this.currentUser?.username;
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

  private validateUsername(username: string, checkUnique: boolean) {
    const value = username.trim();
    if (!value) return 'Username is required';
    if (value.length < 3) return 'Username must be at least 3 characters';
    if (value.length > 50) return 'Username must be 50 characters or less';
    if (!this.usernamePattern.test(value)) {
      return 'Username can use letters, numbers, dot, underscore, and hyphen only';
    }
    if (checkUnique && this.usernameExists(value)) return 'Username already exists';
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

  private validateRole(role: string) {
    if (!role) return 'Role is required';
    return this.roleOptions.some(option => option.value === role) ? '' : 'Select a valid role';
  }

  private validateUserTenant(role: string, tenantId: string) {
    if (role === 'tenant_admin' && !tenantId) return 'Tenant is required for tenant admin';
    if (role === 'tenant_admin' && tenantId === 'default') {
      return 'Tenant admin cannot be assigned to default';
    }
    if (role === 'default_user' && tenantId !== 'default') {
      return 'Default user must use the default tenant';
    }
    return '';
  }

  private firstNewUserValidationError() {
    return (
      this.newUserUsernameError ||
      this.newUserPasswordErrors[0] ||
      this.newUserRoleError ||
      this.newUserTenantError ||
      'Fix user form validation errors'
    );
  }

  private firstEditUserValidationError() {
    return (
      this.editUserRoleError ||
      this.editUserTenantError ||
      this.editUserPasswordErrors[0] ||
      'Fix user form validation errors'
    );
  }

  private resetAnnouncementForm() {
    this.newAnnouncement = {
      title: '',
      message: '',
      type: 'info',
      audience: 'tenant_admins',
      tenant_id: '',
      starts_at: '',
      ends_at: '',
      active: true,
    };
    this.announcementStartDate = '';
    this.announcementStartTime = '';
    this.announcementEndDate = '';
    this.announcementEndTime = '';
  }

  private buildAnnouncementPayload(announcement: AnnouncementDraft): Partial<Announcement> {
    return {
      title: announcement.title.trim(),
      message: announcement.message.trim(),
      type: announcement.type,
      audience: announcement.audience,
      tenant_id: announcement.audience === 'tenant' ? announcement.tenant_id : '',
      starts_at: announcement.starts_at || '',
      ends_at: announcement.ends_at || '',
      active: announcement.active,
    };
  }

  private normalizeAnnouncement(announcement: Announcement): Announcement {
    const targetTenant = this.announcementTenantId(announcement);
    return {
      ...announcement,
      type: announcement.type || 'info',
      audience: announcement.audience || (targetTenant ? 'tenant' : 'all'),
      tenant_id: targetTenant,
      starts_at: announcement.starts_at || announcement.start_at || '',
      ends_at: announcement.ends_at || announcement.end_at || '',
      active: announcement.active ?? announcement.status === 'active',
    };
  }

  private announcementTenantId(announcement: Partial<AnnouncementDraft & Announcement>) {
    if (announcement.tenant_id) return announcement.tenant_id;
    const targetTenants = announcement.target_tenants || [];
    const specificTenant = targetTenants.find(tenant => tenant !== 'all');
    return specificTenant || '';
  }

  private copyText(value: string, successMessage: string) {
    navigator.clipboard.writeText(value).then(
      () => {
        this.showMsg(successMessage, 'success');
        this.cdr.detectChanges();
      },
      () => {
        this.showMsg('Failed to copy to clipboard', 'error');
        this.cdr.detectChanges();
      }
    );
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
    const delay = delays[attempt] ?? delays[delays.length - 1];

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
    const delay = delays[attempt] ?? delays[delays.length - 1];

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

  // ── AI Providers ──────────────────────────────────────────────────────────

  loadProviders() {
    this.loadingProviders = true;
    this.api.listAiProviders().subscribe({
      next: (data: any) => {
        this.providers = data.providers || [];
        this.loadingProviders = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loadingProviders = false;
        this.cdr.detectChanges();
      }
    });
  }

  saveProvider() {
    this.savingProvider = true;
    this.providerMessage = '';
    this.providerError = '';
    this.api.saveAiProvider(this.newProvider).subscribe({
      next: () => {
        this.savingProvider = false;
        this.providerMessage = `Provider "${this.newProvider.name}" saved`;
        this.showAddProviderForm = false;
        this.resetNewProvider();
        this.loadProviders();
        this.cdr.detectChanges();
        setTimeout(() => { this.providerMessage = ''; this.cdr.detectChanges(); }, 3000);
      },
      error: () => {
        this.savingProvider = false;
        this.providerError = 'Failed to save provider';
        this.cdr.detectChanges();
      }
    });
  }

  deleteProvider(name: string) {
    if (!confirm(`Delete provider "${name}"?`)) return;
    this.api.deleteAiProvider(name).subscribe({
      next: () => {
        this.providerMessage = `Provider "${name}" deleted`;
        this.loadProviders();
        this.cdr.detectChanges();
        setTimeout(() => { this.providerMessage = ''; this.cdr.detectChanges(); }, 3000);
      },
      error: () => {
        this.providerError = 'Failed to delete provider';
        this.cdr.detectChanges();
      }
    });
  }

  testProvider(p: AiProvider) {
    this.testingProvider = p.name;
    this.testProviderResult = '';
    const payload = {
      name: p.name, provider_type: p.provider_type,
      api_key: '', model: p.model, base_url: p.base_url,
      endpoint_path: p.endpoint_path || '/v1/chat/completions', msg_format: p.msg_format || 'openai',
    };
    this.api.testAiProvider(payload).subscribe({
      next: (data: any) => {
        this.testingProvider = '';
        this.testProviderResult = data.status === 'ok'
          ? `✓ ${p.name} — OK` : `✗ ${p.name} — ${data.error}`;
        this.cdr.detectChanges();
        setTimeout(() => { this.testProviderResult = ''; this.cdr.detectChanges(); }, 5000);
      },
      error: () => {
        this.testingProvider = '';
        this.testProviderResult = `✗ ${p.name} — request failed`;
        this.cdr.detectChanges();
        setTimeout(() => { this.testProviderResult = ''; this.cdr.detectChanges(); }, 5000);
      }
    });
  }

  testNewProvider() {
    this.testingProvider = '__new__';
    this.testProviderResult = '';
    this.api.testAiProvider(this.newProvider).subscribe({
      next: (data: any) => {
        this.testingProvider = '';
        this.testProviderResult = data.status === 'ok'
          ? '✓ Connection OK — ' + (data.response || '').substring(0, 60)
          : '✗ ' + (data.error || 'No response');
        this.cdr.detectChanges();
        setTimeout(() => { this.testProviderResult = ''; this.cdr.detectChanges(); }, 6000);
      },
      error: () => {
        this.testingProvider = '';
        this.testProviderResult = '✗ Request failed — check URL and key';
        this.cdr.detectChanges();
      }
    });
  }

  resetNewProvider() {
    this.isEditingProvider = false;
    this.newProvider = {
      name: '', provider_type: 'custom', api_key: '', model: '',
      base_url: '', endpoint_path: '/v1/chat/completions',
      msg_format: 'openai', use_case: 'all', priority: 10, enabled: true,
    };
  }

  editProvider(p: AiProvider) {
    this.isEditingProvider = true;
    this.newProvider = { ...p, api_key: '' };
    this.showAddProviderForm = true;
  }

  get defaultBaseUrl(): string {
    switch (this.newProvider.provider_type) {
      case 'openai': return 'https://api.openai.com';
      case 'anthropic': return 'https://api.anthropic.com';
      default: return '';
    }
  }

  get defaultModelPlaceholder(): string {
    switch (this.newProvider.provider_type) {
      case 'openai': return 'gpt-4o-mini';
      case 'anthropic': return 'claude-sonnet-4-6';
      default: return 'e.g. llama-3.3-70b-versatile';
    }
  }

  useCaseLabel(uc: string): string {
    return ({ all: 'All', chat: 'Chat', threat: 'Threat' } as any)[uc] || uc;
  }

  // --- D3 Charts Rendering ---
  renderD3Charts() {
    this.renderResourceUtilizationArea();
    this.renderUserRolesDonut();
    this.renderTopTenantsBar();
    this.renderProcessingEnginesDonut();
  }

  private renderResourceUtilizationArea() {
    const container = d3.select('#resource-area-chart');
    container.selectAll('*').remove();
    if (container.empty()) return;

    const containerNode = container.node() as HTMLElement;
    const width = containerNode.clientWidth || 800;
    const height = 320;
    const margin = { top: 20, right: 30, bottom: 30, left: 50 };

    const svg = container.append('svg')
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet')
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const defs = container.select('svg').append('defs');
    const gradientCpu = defs.append('linearGradient').attr('id', 'cpu-gradient').attr('x1', '0%').attr('y1', '0%').attr('x2', '0%').attr('y2', '100%');
    gradientCpu.append('stop').attr('offset', '0%').attr('stop-color', 'rgba(34, 211, 238, 0.4)');
    gradientCpu.append('stop').attr('offset', '100%').attr('stop-color', 'rgba(34, 211, 238, 0.01)');

    const gradientMem = defs.append('linearGradient').attr('id', 'mem-gradient').attr('x1', '0%').attr('y1', '0%').attr('x2', '0%').attr('y2', '100%');
    gradientMem.append('stop').attr('offset', '0%').attr('stop-color', 'rgba(99, 102, 241, 0.4)');
    gradientMem.append('stop').attr('offset', '100%').attr('stop-color', 'rgba(99, 102, 241, 0.01)');

    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    const data = this.overviewTelemetryHistory.length > 0 ? this.overviewTelemetryHistory : [{ time: new Date(), cpu: 0, mem: 0 }];

    const x = d3.scaleTime().domain(d3.extent(data, (d: any) => d.time) as [Date, Date]).range([0, innerW]);
    const y = d3.scaleLinear().domain([0, 100]).range([innerH, 0]);

    const xAxisGrid = d3.axisBottom(x).tickSize(-innerH).tickFormat(() => '').ticks(5);
    const yAxisGrid = d3.axisLeft(y).tickSize(-innerW).tickFormat(() => '').ticks(5);
    svg.append('g').attr('class', 'chart-grid').attr('transform', `translate(0,${innerH})`).call(xAxisGrid);
    svg.append('g').attr('class', 'chart-grid').call(yAxisGrid);

    const xAxis = d3.axisBottom(x).ticks(5).tickSizeOuter(0).tickFormat((d: any) => d3.timeFormat('%H:%M:%S')(d));
    const yAxis = d3.axisLeft(y).ticks(5).tickSizeOuter(0).tickFormat(d => d + '%');
    svg.append('g').attr('class', 'chart-axis').attr('transform', `translate(0,${innerH})`).call(xAxis).selectAll('text').attr('transform', 'translate(0, 5)');
    svg.append('g').attr('class', 'chart-axis').call(yAxis);

    const cpuLine = d3.line<any>().x(d => x(d.time)).y(d => y(d.cpu)).curve(d3.curveMonotoneX);
    const cpuArea = d3.area<any>().x(d => x(d.time)).y0(innerH).y1(d => y(d.cpu)).curve(d3.curveMonotoneX);
    svg.append('path').datum(data).attr('fill', 'url(#cpu-gradient)').attr('d', cpuArea);
    svg.append('path').datum(data).attr('fill', 'none').attr('stroke', '#22d3ee').attr('stroke-width', 2).attr('d', cpuLine);

    const memLine = d3.line<any>().x(d => x(d.time)).y(d => y(d.mem)).curve(d3.curveMonotoneX);
    const memArea = d3.area<any>().x(d => x(d.time)).y0(innerH).y1(d => y(d.mem)).curve(d3.curveMonotoneX);
    svg.append('path').datum(data).attr('fill', 'url(#mem-gradient)').attr('d', memArea);
    svg.append('path').datum(data).attr('fill', 'none').attr('stroke', '#6366f1').attr('stroke-width', 2).attr('d', memLine);
  }

  private renderUserRolesDonut() {
    const container = d3.select('#user-roles-donut-chart');
    container.selectAll('*').remove();
    if (container.empty()) return;

    const roles: any = { 'Platform Admin': 0, 'Tenant Admin': 0, 'Analyst': 0, 'Viewer': 0, 'Other': 0 };
    for (const u of this.users) {
      if (u.role === 'admin' || u.role === 'super_admin') roles['Platform Admin']++;
      else if (u.role === 'tenant_admin') roles['Tenant Admin']++;
      else if (u.role === 'analyst' || u.role === 'senior_analyst') roles['Analyst']++;
      else if (u.role === 'viewer') roles['Viewer']++;
      else roles['Other']++;
    }
    const data = Object.entries(roles).filter(([k, v]: [string, any]) => v > 0).map(([label, value]) => ({ label, value }));
    if (data.length === 0) data.push({ label: 'No Users', value: 1 });

    const containerNode = container.node() as HTMLElement;
    const width = containerNode.clientWidth || 300;
    const height = 300;
    const radius = Math.min(width, height) / 2 - 20;

    const svg = container.append('svg')
      .attr('width', '100%').attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet')
      .append('g').attr('transform', `translate(${width / 2},${height / 2})`);

    const color = d3.scaleOrdinal<string>().domain(data.map(d => d.label))
      .range(['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#64748b']);
    
    const pie = d3.pie<any>().value(d => d.value).sort(null);
    const arc = d3.arc<any>().innerRadius(radius * 0.6).outerRadius(radius);
    const hoverArc = d3.arc<any>().innerRadius(radius * 0.6).outerRadius(radius + 10);

    const arcs = svg.selectAll('path').data(pie(data)).enter().append('path')
      .attr('d', arc).attr('fill', d => color(d.data.label))
      .attr('stroke', '#0f172a').style('stroke-width', '2px');

    let tooltip: any = d3.select('body').select('.d3-tooltip');
    if (tooltip.empty()) tooltip = d3.select('body').append('div').attr('class', 'd3-tooltip').style('opacity', 0);

    arcs.on('mouseover', function(event, d: any) {
      d3.select(this).transition().duration(200).attr('d', hoverArc);
      tooltip.transition().duration(50).style('opacity', 1);
      tooltip.html(`<strong>${d.data.label}</strong><br/>Users: ${d.data.value}`)
        .style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
    })
    .on('mousemove', function(event) {
      tooltip.style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
    })
    .on('mouseout', function() {
      d3.select(this).transition().duration(200).attr('d', arc);
      tooltip.transition().duration(200).style('opacity', 0);
    });

    const total = d3.sum(data, (d: any) => d.label === 'No Users' ? 0 : Number(d.value));
    svg.append('text').attr('text-anchor', 'middle').attr('dy', '-0.2em').attr('fill', '#f1f5f9')
      .style('font-size', '24px').style('font-weight', '600').text(total);
    svg.append('text').attr('text-anchor', 'middle').attr('dy', '1.2em').attr('fill', '#94a3b8')
      .style('font-size', '12px').text('Total Users');
  }

  private renderTopTenantsBar() {
    const container = d3.select('#tenant-bar-chart');
    container.selectAll('*').remove();
    if (container.empty()) return;

    const tenantUserCounts: any = {};
    for (const t of this.tenants) tenantUserCounts[t.id] = { name: t.name, count: 0 };
    for (const u of this.users) {
      if (u.tenant_id && tenantUserCounts[u.tenant_id]) tenantUserCounts[u.tenant_id].count++;
    }
    
    let data = Object.values(tenantUserCounts).filter((t: any) => t.count > 0).sort((a: any, b: any) => b.count - a.count).slice(0, 5) as {name: string, count: number}[];
    if (data.length === 0) data = [{ name: 'No Data', count: 0 }];

    const containerNode = container.node() as HTMLElement;
    const width = containerNode.clientWidth || 400;
    const height = 300;
    const margin = { top: 20, right: 30, bottom: 40, left: 100 };

    const svg = container.append('svg').attr('width', '100%').attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`).attr('preserveAspectRatio', 'xMidYMid meet')
      .append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    const x = d3.scaleLinear().domain([0, d3.max(data, d => d.count) || 1]).range([0, innerW]);
    const y = d3.scaleBand().domain(data.map(d => d.name)).range([0, innerH]).padding(0.3);

    const xAxisGrid = d3.axisBottom(x).tickSize(-innerH).tickFormat(() => '').ticks(5);
    svg.append('g').attr('class', 'chart-grid').attr('transform', `translate(0,${innerH})`).call(xAxisGrid);

    const xAxis = d3.axisBottom(x).ticks(5).tickSizeOuter(0);
    const yAxis = d3.axisLeft(y).tickSizeOuter(0);

    svg.append('g').attr('class', 'chart-axis').attr('transform', `translate(0,${innerH})`).call(xAxis);
    svg.append('g').attr('class', 'chart-axis').call(yAxis);

    const bars = svg.selectAll('.bar').data(data).enter().append('rect').attr('class', 'bar')
      .attr('x', 0).attr('y', d => y(d.name)!).attr('height', y.bandwidth())
      .attr('width', d => x(d.count)).attr('fill', '#8b5cf6').attr('rx', 4).style('opacity', 0.85);

    let tooltip: any = d3.select('body').select('.d3-tooltip');
    if (tooltip.empty()) tooltip = d3.select('body').append('div').attr('class', 'd3-tooltip').style('opacity', 0);

    bars.on('mouseover', function(event, d: any) {
      d3.select(this).style('opacity', 1).attr('fill', '#a78bfa').style('cursor', 'pointer');
      tooltip.transition().duration(50).style('opacity', 1);
      tooltip.html(`<strong>${d.name}</strong><br/>Users: ${d.count}`)
        .style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
    }).on('mousemove', function(event) {
      tooltip.style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
    }).on('mouseout', function() {
      d3.select(this).style('opacity', 0.85).attr('fill', '#8b5cf6');
      tooltip.transition().duration(200).style('opacity', 0);
    });
  }

  private renderProcessingEnginesDonut() {
    const container = d3.select('#engines-donut-chart');
    container.selectAll('*').remove();
    if (container.empty()) return;

    let up = 0, offline = 0;
    for (const e of this.engines) {
      if (e.status && (e.status.toLowerCase().includes('up') || e.status.toLowerCase().includes('running'))) up++;
      else offline++;
    }
    const data = [
      { label: 'Running', value: up },
      { label: 'Offline / Exited', value: offline }
    ].filter(d => d.value > 0);
    if (data.length === 0) data.push({ label: 'No Engines', value: 1 });

    const containerNode = container.node() as HTMLElement;
    const width = containerNode.clientWidth || 300;
    const height = 300;
    const radius = Math.min(width, height) / 2 - 20;

    const svg = container.append('svg').attr('width', '100%').attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`).attr('preserveAspectRatio', 'xMidYMid meet')
      .append('g').attr('transform', `translate(${width / 2},${height / 2})`);

    const color = d3.scaleOrdinal<string>().domain(['Running', 'Offline / Exited', 'No Engines'])
      .range(['#10b981', '#ef4444', '#64748b']);
    
    const pie = d3.pie<any>().value(d => d.value).sort(null);
    const arc = d3.arc<any>().innerRadius(radius * 0.6).outerRadius(radius);
    const hoverArc = d3.arc<any>().innerRadius(radius * 0.6).outerRadius(radius + 10);

    const arcs = svg.selectAll('path').data(pie(data)).enter().append('path')
      .attr('d', arc).attr('fill', d => color(d.data.label))
      .attr('stroke', '#0f172a').style('stroke-width', '2px');

    let tooltip: any = d3.select('body').select('.d3-tooltip');
    if (tooltip.empty()) tooltip = d3.select('body').append('div').attr('class', 'd3-tooltip').style('opacity', 0);

    arcs.on('mouseover', function(event, d: any) {
      d3.select(this).transition().duration(200).attr('d', hoverArc);
      tooltip.transition().duration(50).style('opacity', 1);
      tooltip.html(`<strong>${d.data.label}</strong><br/>Nodes: ${d.data.value}`)
        .style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
    }).on('mousemove', function(event) {
      tooltip.style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
    }).on('mouseout', function() {
      d3.select(this).transition().duration(200).attr('d', arc);
      tooltip.transition().duration(200).style('opacity', 0);
    });

    const total = d3.sum(data, (d: any) => d.label === 'No Engines' ? 0 : Number(d.value));
    svg.append('text').attr('text-anchor', 'middle').attr('dy', '-0.2em').attr('fill', '#f1f5f9')
      .style('font-size', '24px').style('font-weight', '600').text(total);
    svg.append('text').attr('text-anchor', 'middle').attr('dy', '1.2em').attr('fill', '#94a3b8')
      .style('font-size', '12px').text('Total Nodes');
  }
}
