import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, signal, computed, HostListener } from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
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
  Activity,
  ChartColumn,
  Shield,
  Search,
  Filter,
  ArrowUpDown,
  MoreVertical,
  Building2,
  Fingerprint,
  LayoutDashboard,
  Bell,
  FileText,
  Radio,
  Network,
  Globe,
  Gem,
  Settings,
  UserCircle,
  ChevronRight,
  Server,
  FolderSearch,
  Bot,
  Cpu,
  Plus,
  AlertCircle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  Check,
  ArrowUpCircle,
  RefreshCw,
  Loader,
  Sparkles,
} from 'lucide-angular';
import { Api, SensorKey, SensorAssignment } from '../../services/api/api';
import { AuthService } from '../../services/auth/auth';
import { Subscription } from 'rxjs';
import { BaseChartDirective } from 'ng2-charts';

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
  icon: any;
}

@Component({
  selector: 'app-tenant-admin',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, FormsModule, LucideAngularModule, BaseChartDirective, DatePipe],
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
  ActivityIcon = Activity;
  ChartIcon = ChartColumn;
  ShieldIconAlt = Shield;
  SearchIcon = Search;
  FilterIcon = Filter;
  SortIcon = ArrowUpDown;
  MoreIcon = MoreVertical;
  BuildingIcon = Building2;
  FingerprintIcon = Fingerprint;
  LayoutDashboardIcon = LayoutDashboard;
  BellIcon = Bell;
  FileTextIcon = FileText;
  RadioIcon = Radio;
  NetworkIcon = Network;
  GlobeIcon = Globe;
  GemIcon = Gem;
  SettingsIcon = Settings;
  UserCircleIcon = UserCircle;
  ChevronRightIcon = ChevronRight;
  ServerIcon = Server;
  FolderSearchIcon = FolderSearch;
  BotIcon = Bot;
  CpuIcon = Cpu;
  PlusIcon = Plus;
  AlertCircleIcon = AlertCircle;
  CheckCircle2Icon = CheckCircle2;
  XCircleIcon = XCircle;
  ChevronDownIcon = ChevronDown;
  CheckIcon = Check;
  ArrowUpCircleIcon = ArrowUpCircle;
  RefreshCwIcon = RefreshCw;
  LoaderIcon = Loader;
  SparklesIcon = Sparkles;

  // ── Signals ───────────────────────────────────────────────────────────────

  // Software update
  readonly updateAvailable   = signal(false);
  readonly currentVersion    = signal('');
  readonly latestVersion     = signal('');
  readonly showUpdateDialog  = signal(false);
  readonly updateApplying    = signal(false);
  readonly updateMessage     = signal('');

  // Sensor assignment
  readonly sensorKeys          = signal<SensorKey[]>([]);
  readonly sensorAssignments   = signal<SensorAssignment[]>([]);
  readonly sensorAssignLoading = signal(false);
  readonly sensorAssignSaving  = signal(false);
  readonly pendingSensorSel    = signal<Record<string, string[]>>({});
  readonly sensorDropdownOpen  = signal<Record<string, boolean>>({});
  readonly activeSectionTab    = signal<'users' | 'sensors'>('users');

  // Bulk selection
  readonly selectedUserIds = signal(new Set<string>());

  // Tab navigation
  readonly activeTab = signal<'users' | 'trusted-domains' | 'sessions'>('users');

  // Active sessions
  readonly activeSessions       = signal<any[]>([]);
  readonly sessionsLoading      = signal(false);
  readonly sessionsGrouped      = signal<Record<string, any[]>>({});
  readonly forceLogoutConfirmUser = signal('');

  // Trusted domains
  readonly trustedDomains      = signal<any[]>([]);
  readonly loadingTrustedDomains = signal(false);
  readonly tdNewDomain         = signal('');
  readonly tdNewCategory       = signal('dns_beacon');
  readonly tdNewNote           = signal('');
  readonly tdSaving            = signal(false);
  readonly tdAiLoading         = signal(false);
  readonly tdAiAvailable       = signal<boolean | null>(null);
  readonly tdAiSuggestions     = signal<any[]>([]);

  // Data grid
  readonly searchTerm    = signal('');
  readonly sortField     = signal<keyof TenantUser | 'status'>('username');
  readonly sortAscending = signal(true);

  // Charts
  readonly roleChartData   = signal<any>({ labels: [], datasets: [] });
  readonly statusChartData = signal<any>({ labels: [], datasets: [] });

  // System status
  readonly tenantSystemStatus = signal<'OPERATIONAL' | 'DEGRADED' | 'CHECKING...'>('CHECKING...');

  // Core user state
  readonly currentUser  = signal<any>({});
  readonly tenantId     = signal('');
  readonly tenantName   = signal('Organization');
  readonly users        = signal<TenantUser[]>([]);
  readonly loading      = signal(false);
  readonly saving       = signal(false);
  readonly showForm     = signal(false);
  readonly editingUser  = signal<TenantUser | null>(null);
  readonly message      = signal('');
  readonly messageType  = signal<'success' | 'error'>('success');

  // Username/password validation state
  readonly usernameStatus   = signal<'idle' | 'checking' | 'available' | 'taken' | 'unavailable'>('idle');
  readonly usernameTouched  = signal(false);
  readonly passwordTouched  = signal(false);

  // ── Computed signals ─────────────────────────────────────────────────────

  readonly activeUsers  = computed(() => this.users().filter(u => u.active !== false).length);
  readonly analystUsers = computed(() => this.users().filter(u => u.role === 'analyst' || u.role === 'senior_analyst').length);
  readonly viewerUsers  = computed(() => this.users().filter(u => u.role === 'viewer').length);
  readonly assignableUsers = computed(() => this.users());

  readonly tenantOwnDomains = computed(() => this.trustedDomains().filter(d => d.scope === 'tenant'));
  readonly globalDomains    = computed(() => this.trustedDomains().filter(d => d.scope === 'global'));

  readonly pageTitle    = computed(() => 'Tenant Users');
  readonly pageSubtitle = computed(() => `Manage analysts and page access for ${this.tenantName()}.`);

  readonly filteredAndSortedUsers = computed(() => {
    let result = this.users();
    const term = this.searchTerm();
    if (term) {
      const t = term.toLowerCase();
      result = result.filter(u =>
        u.username.toLowerCase().includes(t) ||
        this.getRoleLabel(u.role).toLowerCase().includes(t)
      );
    }
    const field = this.sortField();
    const asc   = this.sortAscending();
    return [...result].sort((a, b) => {
      let valA: any = a[field as keyof TenantUser];
      let valB: any = b[field as keyof TenantUser];
      if (field === 'status') { valA = a.active ? 1 : 0; valB = b.active ? 1 : 0; }
      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();
      if (valA < valB) return asc ? -1 : 1;
      if (valA > valB) return asc ? 1 : -1;
      return 0;
    });
  });

  // ── Plain mutable state (ngModel two-way binding) ─────────────────────────

  userForm = {
    username: '',
    password: '',
    role: 'analyst',
    active: true,
    permissions: [
      'dashboard', 'alerts', 'assets', 'logs', 'live',
      'network-map', 'intel', 'health', 'evidence',
    ] as string[],
  };

  // ── Constants ─────────────────────────────────────────────────────────────

  readonly donutChartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '78%',
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0C1220',
        titleColor: '#EFF6FF',
        bodyColor: '#94A3B8',
        borderColor: 'rgba(255,255,255,0.10)',
        borderWidth: 1,
        padding: 14,
        cornerRadius: 10,
        displayColors: true,
        boxWidth: 8,
        boxHeight: 8
      }
    },
    elements: {
      arc: { borderWidth: 4, borderColor: '#0B1120', borderRadius: 4, hoverOffset: 6 }
    }
  };

  readonly permissionOptions: PermissionOption[] = [
    { key: 'dashboard',    label: 'Dashboard',     description: 'Operational overview and key metrics',      icon: LayoutDashboard },
    { key: 'alerts',       label: 'Alerts',         description: 'Correlation hits and alert triage',         icon: Bell },
    { key: 'assets',       label: 'Assets',         description: 'Asset inventory and tracking',              icon: Server },
    { key: 'logs',         label: 'Network Logs',   description: 'Agent-Z and Agent-S event records',         icon: FileText },
    { key: 'live',         label: 'Live Stream',    description: 'Real-time network activity',                icon: Radio },
    { key: 'network-map',  label: 'Network Map',    description: 'Source and destination topology',           icon: Network },
    { key: 'intel',        label: 'Threat Intel',   description: 'IOC lookup and enrichment',                 icon: Globe },
    { key: 'health',       label: 'System Health',  description: 'Service and sensor status',                 icon: Activity },
    { key: 'rules',        label: 'Rules View',     description: 'Read-only detection rule access',           icon: Gem },
    { key: 'evidence',     label: 'Evidence',       description: 'Evidence and artifact locker',              icon: FolderSearch },
    { key: 'soar',         label: 'SOAR View',      description: 'Read-only automation visibility',           icon: Settings },
    { key: 'ai-activity',  label: 'AI Activity',    description: 'Aria analyst interactions',                 icon: Bot },
    { key: 'ai-report',    label: 'AI Report',      description: 'AI-generated security reports',             icon: Bot },
  ];

  readonly permissionCategories = [
    {
      title: 'CORE',
      options: [
        this.permissionOptions.find(p => p.key === 'dashboard')!,
        this.permissionOptions.find(p => p.key === 'alerts')!,
        this.permissionOptions.find(p => p.key === 'assets')!,
      ]
    },
    {
      title: 'NETWORK',
      options: [
        this.permissionOptions.find(p => p.key === 'logs')!,
        this.permissionOptions.find(p => p.key === 'network-map')!,
        this.permissionOptions.find(p => p.key === 'live')!,
      ]
    },
    {
      title: 'SECURITY',
      options: [
        this.permissionOptions.find(p => p.key === 'intel')!,
        this.permissionOptions.find(p => p.key === 'rules')!,
        this.permissionOptions.find(p => p.key === 'evidence')!,
      ]
    },
    {
      title: 'OPERATIONS',
      options: [
        this.permissionOptions.find(p => p.key === 'health')!,
        this.permissionOptions.find(p => p.key === 'soar')!,
        this.permissionOptions.find(p => p.key === 'ai-activity')!,
        this.permissionOptions.find(p => p.key === 'ai-report')!,
      ]
    }
  ];

  readonly roleOptions = [
    { value: 'analyst',        label: 'Analyst',        tier: 'blue' },
    { value: 'senior_analyst', label: 'Senior Analyst', tier: 'violet' },
    { value: 'viewer',         label: 'Viewer',         tier: 'slate' },
  ];

  // ── Private internals ────────────────────────────────────────────────────

  private statusInterval: ReturnType<typeof setInterval> | null = null;
  private usernameTimer: ReturnType<typeof setTimeout> | null = null;
  private usernameCheckSub: Subscription | null = null;
  private readonly usernamePattern = /^[A-Za-z0-9._-]+$/;
  private permLabelsCache = new Map<string, string[]>();

  // trackBy functions — prevent DOM destruction/recreation on every signal change
  trackByUserId(_: number, user: TenantUser) { return user.id; }
  trackByUsername(_: number, name: string)   { return name; }
  trackByIndex(i: number)                    { return i; }

  constructor(
    private api: Api,
    private auth: AuthService,
    private router: Router,
  ) {}

  ngOnInit() {
    const user = this.auth.getUser() || {};
    this.currentUser.set(user);
    this.tenantId.set(user.tenant_id || 'default');
    this.tenantName.set(this.formatTenantName(user.tenant_id || 'default'));

    if (!['admin', 'super_admin', 'tenant_admin'].includes(user.role)) {
      this.router.navigate(['/dashboard']);
      return;
    }

    this.refreshTenantSystemStatus();
    this.statusInterval = setInterval(() => this.refreshTenantSystemStatus(), 10000);

    this.loadUsers();
    this.loadSensorData();
    this.checkForUpdates();
  }

  ngOnDestroy(): void {
    this.clearUsernameCheck();
    if (this.statusInterval) clearInterval(this.statusInterval);
  }

  // ── Regular getters (depend on userForm — plain object, not a signal) ─────

  get usernameError() {
    return this.validateUsername(this.userForm.username);
  }

  get usernameFeedback() {
    const status = this.usernameStatus();
    if (this.editingUser() || this.usernameError) return '';
    if (status === 'checking')   return 'Checking username availability...';
    if (status === 'available')  return 'Username is available';
    if (status === 'taken')      return 'Username already exists';
    if (status === 'unavailable') return 'Could not check username availability';
    return '';
  }

  get usernameFeedbackType(): 'neutral' | 'success' | 'error' {
    const status = this.usernameStatus();
    if (status === 'available') return 'success';
    if (status === 'taken' || status === 'unavailable') return 'error';
    return 'neutral';
  }

  get passwordErrors() {
    return this.validatePassword(this.userForm.password, this.userForm.username, !this.editingUser());
  }

  get canSaveUser() {
    return (
      !this.saving() &&
      !this.usernameError &&
      this.passwordErrors.length === 0 &&
      (this.editingUser() || this.usernameStatus() === 'available')
    );
  }

  // ── Users ──────────────────────────────────────────────────────────────────

  loadUsers() {
    this.loading.set(true);
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.permLabelsCache.clear();
        const tid = this.tenantId();
        this.users.set(
          (data.users || [])
            .filter((u: TenantUser) => u.tenant_id === tid)
            .filter((u: TenantUser) => this.isManageableTenantUser(u))
            .map((u: TenantUser) => ({
              ...u,
              active: u.active !== false,
              permissions: this.normalizePermissions(u.permissions, u.role),
            }))
        );
        this.updateCharts();
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
        this.showMessage('Failed to load tenant users', 'error');
      },
    });
  }

  // ── Sensor assignment ─────────────────────────────────────────────────────

  loadSensorData() {
    this.sensorAssignLoading.set(true);
    const tid = this.tenantId();

    this.api.getSensorKeys().subscribe({
      next: (keys) => {
        this.sensorKeys.set(keys.filter(k => k.tenant_id === tid && k.active !== false));
      },
      error: () => {}
    });

    this.api.getSensorAssignments().subscribe({
      next: (res) => {
        this.sensorAssignments.set(res.assignments || []);
        this.sensorAssignLoading.set(false);
      },
      error: () => { this.sensorAssignLoading.set(false); }
    });
  }

  getUserSensorIds(userId: string): string[] {
    return this.sensorAssignments()
      .filter(a => a.user_id === userId)
      .map(a => a.sensor_id);
  }

  getSensorByPrefix(prefix: string): SensorKey | undefined {
    return this.sensorKeys().find(k => k.key_prefix === prefix);
  }

  getSensorLabel(prefix: string): string {
    const s = this.getSensorByPrefix(prefix);
    return s ? (s.name || s.key_prefix) : prefix;
  }

  getAvailableSensors(userId: string): SensorKey[] {
    const assigned = new Set(this.getUserSensorIds(userId));
    return this.sensorKeys().filter(k => !assigned.has(k.key_prefix));
  }

  @HostListener('document:click')
  closeAllSensorDropdowns() {
    const open = this.sensorDropdownOpen();
    if (Object.keys(open).some(k => open[k])) {
      this.sensorDropdownOpen.set({});
    }
  }

  toggleSensorDropdown(userId: string, event: Event) {
    event.stopPropagation();
    const wasOpen = !!this.sensorDropdownOpen()[userId];
    this.sensorDropdownOpen.set(wasOpen ? {} : { [userId]: true });
  }

  isSensorSelected(userId: string, sensorId: string): boolean {
    return (this.pendingSensorSel()[userId] || []).includes(sensorId);
  }

  toggleSensorSelection(userId: string, sensorId: string) {
    this.pendingSensorSel.update(sel => {
      const current = sel[userId] || [];
      return {
        ...sel,
        [userId]: current.includes(sensorId)
          ? current.filter(id => id !== sensorId)
          : [...current, sensorId]
      };
    });
  }

  getSelectedCount(userId: string): number {
    return (this.pendingSensorSel()[userId] || []).length;
  }

  addSensorsToUser(userId: string) {
    const toAssign = [...(this.pendingSensorSel()[userId] || [])];
    if (toAssign.length === 0) return;

    this.sensorAssignSaving.set(true);
    this.sensorDropdownOpen.set({});
    const total = toAssign.length;
    let done = 0;
    let errors = 0;

    for (const sensorId of toAssign) {
      this.api.assignSensor(userId, sensorId).subscribe({
        next: () => {
          this.sensorAssignments.update(s => [...s, { user_id: userId, sensor_id: sensorId }]);
          done++;
          if (done + errors === total) {
            this.pendingSensorSel.update(s => ({ ...s, [userId]: [] }));
            this.sensorAssignSaving.set(false);
            this.showMessage(
              errors === 0
                ? `${total} sensor(s) assigned. Analyst must re-login for changes to take effect.`
                : `${total - errors} assigned, ${errors} failed.`,
              errors === 0 ? 'success' : 'error'
            );
          }
        },
        error: () => {
          errors++;
          if (done + errors === total) {
            this.pendingSensorSel.update(s => ({ ...s, [userId]: [] }));
            this.sensorAssignSaving.set(false);
            this.showMessage(`${total - errors} assigned, ${errors} failed.`, 'error');
          }
        }
      });
    }
  }

  removeSensorFromUser(userId: string, sensorId: string) {
    this.sensorAssignSaving.set(true);
    this.api.unassignSensor(userId, sensorId).subscribe({
      next: () => {
        this.sensorAssignments.update(s =>
          s.filter(a => !(a.user_id === userId && a.sensor_id === sensorId))
        );
        this.sensorAssignSaving.set(false);
        this.showMessage('Sensor removed. Analyst must log out and back in for changes to take effect.', 'success');
      },
      error: () => {
        this.sensorAssignSaving.set(false);
        this.showMessage('Failed to remove sensor assignment', 'error');
      }
    });
  }

  // ── User form ─────────────────────────────────────────────────────────────

  openCreateForm() {
    this.clearUsernameCheck();
    this.usernameTouched.set(false);
    this.passwordTouched.set(false);
    this.editingUser.set(null);
    this.userForm = {
      username: '',
      password: '',
      role: 'analyst',
      active: true,
      permissions: this.defaultPermissionsFor('analyst'),
    };
    this.showForm.set(true);
  }

  openEditForm(user: TenantUser) {
    this.clearUsernameCheck();
    this.usernameTouched.set(false);
    this.passwordTouched.set(false);
    this.editingUser.set(user);
    this.userForm = {
      username: user.username,
      password: '',
      role: user.role,
      active: user.active !== false,
      permissions: this.normalizePermissions(user.permissions, user.role),
    };
    this.showForm.set(true);
  }

  closeForm() {
    this.clearUsernameCheck();
    this.showForm.set(false);
  }

  onUsernameChange() {
    this.clearUsernameCheck();

    if (this.editingUser() || this.usernameError) {
      this.usernameStatus.set('idle');
      return;
    }

    const username = this.userForm.username.trim();
    this.usernameStatus.set('checking');

    this.usernameTimer = setTimeout(() => {
      this.usernameCheckSub = this.auth.checkUsername(username).subscribe({
        next: (res) => {
          if (this.userForm.username.trim() !== username) return;
          this.usernameStatus.set(res.exists ? 'taken' : 'available');
        },
        error: () => {
          if (this.userForm.username.trim() !== username) return;
          this.usernameStatus.set('unavailable');
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

    const editing = this.editingUser();
    if (editing) {
      this.saving.set(true);
      const permissions = this.normalizePermissions(this.userForm.permissions, this.userForm.role);
      const userId    = editing.id;
      const wasActive = editing.active !== false;
      const nowActive = this.userForm.active;
      const statusChanged = wasActive !== nowActive;

      this.api.updateUserPermissions(userId, permissions).subscribe({
        next: (data: any) => {
          if (data.status !== 'ok') {
            this.saving.set(false);
            this.showMessage(data.message || 'Failed to update user access', 'error');
            return;
          }

          const afterPermissions = () => {
            if (statusChanged) {
              this.api.setUserStatus(userId, nowActive).subscribe({
                next: (statusData: any) => {
                  if (statusData.status === 'ok') {
                    this.afterSaveComplete(userId, permissions, nowActive);
                  } else {
                    this.saving.set(false);
                    this.showMessage(statusData.message || 'Permissions saved but failed to update status', 'error');
                  }
                },
                error: () => {
                  this.saving.set(false);
                  this.showMessage('Permissions saved but failed to update status', 'error');
                }
              });
            } else {
              this.afterSaveComplete(userId, permissions, nowActive);
            }
          };

          if (this.userForm.password.trim()) {
            this.api.resetUserPassword(userId, this.userForm.password).subscribe({
              next: (pwdData: any) => {
                if (pwdData.status === 'ok') {
                  afterPermissions();
                } else {
                  this.saving.set(false);
                  this.showMessage(pwdData.message || 'Access updated, but failed to reset password', 'error');
                }
              },
              error: () => {
                this.saving.set(false);
                this.showMessage('Access updated, but failed to reset password', 'error');
              }
            });
          } else {
            afterPermissions();
          }
        },
        error: () => {
          this.saving.set(false);
          this.showMessage('Failed to update user access', 'error');
        },
      });
      return;
    }

    // Create new user
    this.saving.set(true);
    const permissions = this.normalizePermissions(this.userForm.permissions, this.userForm.role);
    this.api.createUser({
      username: this.userForm.username.trim(),
      password: this.userForm.password,
      role: this.userForm.role,
      tenant_id: this.tenantId(),
      permissions,
    }).subscribe({
      next: (data: any) => {
        this.saving.set(false);
        if (data.status === 'ok') {
          this.closeForm();
          this.showMessage('User created for this tenant', 'success');
          this.loadUsers();
        } else {
          this.showMessage(data.message || 'Failed to create user', 'error');
        }
      },
      error: () => {
        this.saving.set(false);
        this.showMessage('Failed to create user', 'error');
      },
    });
  }

  private afterSaveComplete(userId: string, permissions: string[], active: boolean) {
    this.saving.set(false);
    this.users.update(list =>
      list.map(u => u.id === userId ? { ...u, permissions, active } : u)
    );
    this.updateCharts();
    this.closeForm();
    this.showMessage(
      active ? 'User updated successfully' : 'User disabled successfully',
      'success'
    );
  }

  deleteUser(user: TenantUser) {
    if (!confirm(`Delete user "${user.username}" from this tenant?`)) return;
    this.api.deleteUser(user.id).subscribe({
      next: () => {
        this.users.update(list => list.filter(u => u.id !== user.id));
        this.showMessage('User deleted', 'success');
      },
      error: () => this.showMessage('Failed to delete user', 'error'),
    });
  }

  togglePermission(permission: string) {
    const selected = new Set(this.userForm.permissions);
    if (selected.has(permission)) selected.delete(permission);
    else selected.add(permission);
    this.userForm.permissions = Array.from(selected);
  }

  hasPermission(permission: string) {
    return this.userForm.permissions.includes(permission);
  }

  onRoleChange() {
    if (!this.editingUser()) {
      this.userForm.permissions = this.defaultPermissionsFor(this.userForm.role);
    }
  }

  selectRole(value: string) {
    if (this.editingUser()) return;
    this.userForm.role = value;
    this.onRoleChange();
  }

  getUserStatus(user: TenantUser): 'active' | 'disabled' {
    return user.active !== false ? 'active' : 'disabled';
  }

  getRoleLabel(role: string) {
    return this.roleOptions.find(o => o.value === role)?.label || role;
  }

  getPermissionLabels(user: TenantUser): string[] {
    const hit = this.permLabelsCache.get(user.id);
    if (hit) return hit;
    const permissions = this.normalizePermissions(user.permissions, user.role);
    const labels = this.permissionOptions
      .filter(o => permissions.includes(o.key))
      .map(o => o.label);
    this.permLabelsCache.set(user.id, labels);
    return labels;
  }

  // ── Data grid ─────────────────────────────────────────────────────────────

  toggleSort(field: keyof TenantUser | 'status') {
    if (this.sortField() === field) {
      this.sortAscending.update(v => !v);
    } else {
      this.sortField.set(field);
      this.sortAscending.set(true);
    }
  }

  // ── Bulk actions ──────────────────────────────────────────────────────────

  toggleSelection(userId: string) {
    this.selectedUserIds.update(s => {
      const next = new Set(s);
      if (next.has(userId)) next.delete(userId); else next.add(userId);
      return next;
    });
  }

  toggleAll() {
    const visible = this.filteredAndSortedUsers();
    this.selectedUserIds.update(s => {
      if (visible.length > 0 && visible.every(u => s.has(u.id))) {
        return new Set<string>();
      }
      return new Set(visible.map(u => u.id));
    });
  }

  isAllSelected(): boolean {
    const visible = this.filteredAndSortedUsers();
    const sel = this.selectedUserIds();
    return visible.length > 0 && visible.every(u => sel.has(u.id));
  }

  bulkUpdateStatus(active: boolean) {
    const ids = this.selectedUserIds();
    if (ids.size === 0) return;
    const action = active ? 'enable' : 'disable';
    if (!confirm(`Are you sure you want to ${action} ${ids.size} users?`)) return;

    let completed = 0;
    const total = ids.size;
    this.saving.set(true);

    ids.forEach(id => {
      this.api.setUserStatus(id, active).subscribe({
        next: () => {
          completed++;
          if (completed === total) {
            this.selectedUserIds.set(new Set());
            this.saving.set(false);
            this.showMessage(`Successfully ${action}d ${total} users`, 'success');
            this.loadUsers();
          }
        },
        error: () => {
          completed++;
          if (completed === total) {
            this.saving.set(false);
            this.loadUsers();
          }
        }
      });
    });
  }

  exportToCSV() {
    const data = this.filteredAndSortedUsers().map(u => ({
      Username: u.username,
      Role: this.getRoleLabel(u.role),
      Status: u.active ? 'Active' : 'Disabled',
      Created: u.created_at ? new Date(u.created_at).toLocaleString() : 'Unknown',
      Permissions: this.normalizePermissions(u.permissions, u.role).join('; ')
    }));

    if (data.length === 0) { this.showMessage('No users to export', 'error'); return; }

    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(','),
      ...data.map(row => headers.map(h => `"${(row as any)[h]}"`).join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url  = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `tenant_users_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  // ── System status polling ─────────────────────────────────────────────────

  private refreshTenantSystemStatus() {
    this.api.getSensorKeys().subscribe({
      next: (sensors: any[]) => {
        let healthyPipeline = false;
        if (sensors.length === 0) {
          healthyPipeline = true;
        } else {
          healthyPipeline = sensors.some(s =>
            s.active !== false &&
            (this.isRunning(s['agent-z']) || this.isRunning(s['agent-s']) || this.isRunning(s.vector))
          );
        }

        this.api.getDashboardStats().subscribe({
          next: data => {
            const svc = data?.services || {};
            const platformHealthy =
              this.isRunning(svc.kafka) &&
              this.isRunning(svc.clickhouse) &&
              this.isRunning(svc.engine || 'running');
            this.tenantSystemStatus.set(healthyPipeline && platformHealthy ? 'OPERATIONAL' : 'DEGRADED');
          },
          error: () => { this.tenantSystemStatus.set('DEGRADED'); },
        });
      },
      error: () => { this.tenantSystemStatus.set('DEGRADED'); },
    });
  }

  private isRunning(status: unknown) {
    const value = String(status || '').toLowerCase().trim();
    if (['running', 'healthy', 'ok', 'up', 'active', 'started', 'unknown'].includes(value)) return true;
    return /^\d+$/.test(value);
  }

  // ── Trusted domains ───────────────────────────────────────────────────────

  loadTrustedDomains() {
    this.loadingTrustedDomains.set(true);
    this.api.listTrustedDomains().subscribe({
      next: (data: any) => {
        this.trustedDomains.set(data.domains || []);
        this.loadingTrustedDomains.set(false);
      },
      error: () => { this.loadingTrustedDomains.set(false); },
    });
  }

  addTrustedDomain() {
    const d = this.tdNewDomain().trim().toLowerCase();
    if (!d) return;
    this.tdSaving.set(true);
    this.api.addTrustedDomain(d, this.tdNewCategory(), 'own', this.tdNewNote()).subscribe({
      next: () => {
        this.tdNewDomain.set('');
        this.tdNewNote.set('');
        this.tdSaving.set(false);
        this.loadTrustedDomains();
      },
      error: () => { this.tdSaving.set(false); },
    });
  }

  deleteTenantTrustedDomain(domain: string, tenantId: string) {
    this.api.deleteTrustedDomain(domain, tenantId).subscribe({
      next: () => {
        this.trustedDomains.update(list =>
          list.filter(d => !(d.domain === domain && d.tenant_id === tenantId))
        );
      },
      error: () => {},
    });
  }

  runAiSuggest() {
    this.tdAiLoading.set(true);
    this.tdAiSuggestions.set([]);
    this.api.aiSuggestTrustedDomains().subscribe({
      next: (data: any) => {
        this.tdAiAvailable.set(data.ai_available !== false);
        this.tdAiSuggestions.set((data.suggestions || []).filter((s: any) => s.verdict === 'TRUSTED'));
        this.tdAiLoading.set(false);
      },
      error: () => { this.tdAiLoading.set(false); },
    });
  }

  approveTdSuggestion(s: any) {
    this.api.addTrustedDomain(s.domain, 'dns_beacon', 'own', s.reason || '').subscribe({
      next: () => {
        this.tdAiSuggestions.update(list => list.filter(x => x.domain !== s.domain));
        this.loadTrustedDomains();
      },
      error: () => {},
    });
  }

  dismissTdSuggestion(domain: string) {
    this.tdAiSuggestions.update(list => list.filter(s => s.domain !== domain));
  }

  // ── Tab navigation ────────────────────────────────────────────────────────

  switchTab(tab: 'users' | 'trusted-domains' | 'sessions') {
    this.activeTab.set(tab);
    if (tab === 'trusted-domains') this.loadTrustedDomains();
    if (tab === 'sessions')        this.loadActiveSessions();
  }

  // ── Active sessions ───────────────────────────────────────────────────────

  loadActiveSessions() {
    this.sessionsLoading.set(true);
    this.api.getActiveSessions().subscribe({
      next: (data: any) => {
        const sessions: any[] = data.sessions || [];
        const grouped: Record<string, any[]> = {};
        for (const s of sessions) {
          if (!grouped[s.username]) grouped[s.username] = [];
          grouped[s.username].push(s);
        }
        this.activeSessions.set(sessions);
        this.sessionsGrouped.set(grouped);
        this.sessionsLoading.set(false);
      },
      error: () => { this.sessionsLoading.set(false); }
    });
  }

  sessionUsernames(): string[] {
    return Object.keys(this.sessionsGrouped()).sort();
  }

  promptForceLogout(username: string) {
    this.forceLogoutConfirmUser.set(username);
  }

  cancelForceLogout() {
    this.forceLogoutConfirmUser.set('');
  }

  confirmForceLogout(username: string) {
    this.api.forceLogoutUser(username).subscribe({
      next: (data: any) => {
        this.forceLogoutConfirmUser.set('');
        this.showMessage(
          `${username} signed out from ${data.sessions_terminated} device(s)`,
          'success'
        );
        this.loadActiveSessions();
      },
      error: () => {
        this.showMessage('Failed to sign out user', 'error');
        this.forceLogoutConfirmUser.set('');
      }
    });
  }

  formatLoginTime(ts: string): string {
    if (!ts) return '—';
    return new Date(parseInt(ts, 10) * 1000).toLocaleString();
  }

  // ── Software update ───────────────────────────────────────────────────────

  checkForUpdates() {
    this.api.getVersionStatus().subscribe({
      next: (data: any) => {
        this.currentVersion.set(data.current_version || '');
        this.latestVersion.set(data.latest_version  || '');
        this.updateAvailable.set(!!data.update_available);
      },
      error: () => {}  // cloud deployments return 403/404 — silently ignore
    });
  }

  openUpdateDialog() {
    this.showUpdateDialog.set(true);
    this.updateMessage.set('');
  }

  closeUpdateDialog() {
    this.showUpdateDialog.set(false);
  }

  confirmApplyUpdate() {
    this.updateApplying.set(true);
    this.updateMessage.set('');

    // Stop system-status polling while engine restarts
    if (this.statusInterval) {
      clearInterval(this.statusInterval);
      this.statusInterval = null;
    }

    const resumeStatusPolling = () => {
      this.statusInterval = setInterval(() => this.refreshTenantSystemStatus(), 10000);
    };

    this.api.applyUpdate().subscribe({
      next: (data: any) => {
        this.updateMessage.set(data.message || 'Update triggered. Services restarting…');
        this.updateApplying.set(false);
        this.updateAvailable.set(false);

        let attempts = 0;
        let pendingSub: Subscription | null = null;
        const poll = setInterval(() => {
          if (pendingSub) { pendingSub.unsubscribe(); pendingSub = null; }
          pendingSub = this.api.getVersionStatus().subscribe({
            next: (v: any) => {
              if (v.current_version === this.latestVersion() || ++attempts > 36) {
                clearInterval(poll);
                pendingSub = null;
                this.currentVersion.set(v.current_version);
                this.latestVersion.set(v.latest_version || '');
                this.updateAvailable.set(!!v.update_available);
                this.showUpdateDialog.set(false);
                this.showMessage(`Updated to v${v.current_version}`, 'success');
                resumeStatusPolling();
              }
            },
            error: () => { attempts++; }
          });
        }, 5000);
      },
      error: (err: any) => {
        this.updateMessage.set(err?.error?.message || 'Update request failed');
        this.updateApplying.set(false);
        resumeStatusPolling();
      }
    });
  }

  // ── Charts ────────────────────────────────────────────────────────────────

  private updateCharts() {
    this.generateRoleChart();
    this.generateStatusChart();
  }

  private generateRoleChart() {
    const list = this.users();
    const analyst = list.filter(u => u.role === 'analyst').length;
    const senior  = list.filter(u => u.role === 'senior_analyst').length;
    const viewer  = list.filter(u => u.role === 'viewer').length;

    this.roleChartData.set({
      labels: ['Analyst', 'Senior Analyst', 'Viewer'],
      datasets: [{
        data: [analyst, senior, viewer],
        backgroundColor:      ['#0EA5E9', '#8B5CF6', '#10B981'],
        hoverBackgroundColor: ['#38BDF8', '#A78BFA', '#34D399'],
        borderWidth: 4,
        borderColor: '#0B1120',
        hoverOffset: 6
      }]
    });
  }

  private generateStatusChart() {
    const active   = this.activeUsers();
    const disabled = this.users().length - active;

    this.statusChartData.set({
      labels: ['Active', 'Disabled'],
      datasets: [{
        data: [active, disabled],
        backgroundColor:      ['#10B981', '#475569'],
        hoverBackgroundColor: ['#34D399', '#64748B'],
        borderWidth: 4,
        borderColor: '#0B1120',
        hoverOffset: 6
      }]
    });
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private defaultPermissionsFor(role: string): string[] {
    if (role === 'viewer') return ['dashboard', 'alerts', 'health'];
    if (role === 'senior_analyst') return this.permissionOptions.map(p => p.key);
    return ['dashboard', 'alerts', 'logs', 'live', 'network-map', 'intel', 'health'];
  }

  private normalizePermissions(value: unknown, role: string): string[] {
    const permissions = Array.isArray(value)
      ? value
      : typeof value === 'string'
        ? value.split(',')
        : this.defaultPermissionsFor(role);

    return Array.from(new Set(
      permissions
        .map(p => String(p).trim())
        .filter(Boolean)
        .map(p => p.endsWith(':view') ? p.replace(':view', '') : p)
        .map(p => p === 'network' ? 'network-map' : p)
    ));
  }

  private isManageableTenantUser(user: TenantUser) {
    const adminRoles = ['admin', 'super_admin', 'tenant_admin'];
    if (adminRoles.includes(user.role)) return false;
    const me = this.currentUser();
    return user.id !== me?.id && user.username !== me?.username;
  }

  private showMessage(message: string, type: 'success' | 'error') {
    this.message.set(message);
    this.messageType.set(type);
    setTimeout(() => this.message.set(''), 5000);
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
    if (!this.editingUser() && this.localUsernameExists(value)) return 'Username already exists';
    return '';
  }

  private validatePassword(password: string, username: string, required: boolean) {
    const value = password || '';
    const errors: string[] = [];
    if (!value) { if (required) errors.push('Password is required'); return errors; }
    if (value.length < 8)            errors.push('Password must be at least 8 characters');
    if (!/[A-Z]/.test(value))        errors.push('Password needs an uppercase letter');
    if (!/[a-z]/.test(value))        errors.push('Password needs a lowercase letter');
    if (!/[0-9]/.test(value))        errors.push('Password needs a number');
    if (!/[^A-Za-z0-9]/.test(value)) errors.push('Password needs a special character');
    if (username.trim() && value.toLowerCase() === username.trim().toLowerCase()) {
      errors.push('Password cannot be the same as username');
    }
    return errors;
  }

  private firstValidationError() {
    const status = this.usernameStatus();
    if (this.usernameError) return this.usernameError;
    if (!this.editingUser() && status === 'checking')     return 'Wait for username availability check';
    if (!this.editingUser() && status === 'taken')        return 'Username already exists';
    if (!this.editingUser() && status === 'unavailable')  return 'Could not check username availability';
    if (!this.editingUser() && status !== 'available')    return 'Confirm username availability';
    return this.passwordErrors[0] || '';
  }

  private localUsernameExists(username: string) {
    const normalized = username.trim().toLowerCase();
    return this.users().some(u => u.username?.trim().toLowerCase() === normalized);
  }

  private clearUsernameCheck() {
    if (this.usernameTimer) { clearTimeout(this.usernameTimer); this.usernameTimer = null; }
    this.usernameCheckSub?.unsubscribe();
    this.usernameCheckSub = null;
    this.usernameStatus.set('idle');
  }
}
