import {
  Component, Input, OnInit, OnDestroy, ChangeDetectionStrategy,
  signal, computed, ViewEncapsulation,
} from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Users as UsersLucide, UserPlus, ShieldCheck, Lock, Edit, Trash2, X, Save,
  Activity, ChartColumn, Shield, Search, ArrowUpDown, MoreVertical,
  LayoutDashboard, Bell, FileText, Radio, Network, Globe, Gem, Settings,
  UserCircle, ChevronRight, Server, FolderSearch, Bot, Cpu, Plus,
  AlertCircle, XCircle, ChevronDown, Check, RotateCcw,
  Database, ShieldAlert, ScrollText,
} from 'lucide-angular';
import { Api, SensorKey, SensorAssignment } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
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
  // features that unlock this page — empty means always visible
  requiredFeatures?: string[];
}

@Component({
  selector: 'app-users',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule, BaseChartDirective, DatePipe],
  templateUrl: './users.html',
  styleUrl: './users.css',
})
export class UsersSection implements OnInit, OnDestroy {
  @Input() tenantId = '';
  @Input() tenantName = 'Organization';
  @Input() set tenantFeatures(v: string[]) { if (v?.length) this._tenantFeatures.set(v); }
  /** Sensor keys forwarded from the parent shell (already fetched in the status poll).
   *  When provided, loadSensorData() skips its own getSensorKeys() call. */
  @Input() set parentSensorKeys(keys: any[]) {
    if (keys?.length) {
      const tid = this.tenantId;
      this.sensorKeys.set(keys.filter((k: any) => k.tenant_id === tid && k.active !== false));
    }
  }
  private readonly _tenantFeatures = signal<string[]>([]);

  UsersIcon        = UsersLucide;
  UserPlusIcon     = UserPlus;
  ShieldIcon       = ShieldCheck;
  LockIcon         = Lock;
  EditIcon         = Edit;
  TrashIcon        = Trash2;
  XIcon            = X;
  SaveIcon         = Save;
  ActivityIcon     = Activity;
  ChartIcon        = ChartColumn;
  ShieldIconAlt    = Shield;
  SearchIcon       = Search;
  SortIcon         = ArrowUpDown;
  MoreIcon         = MoreVertical;
  LayoutDashboardIcon = LayoutDashboard;
  BellIcon         = Bell;
  FileTextIcon     = FileText;
  RadioIcon        = Radio;
  NetworkIcon      = Network;
  GlobeIcon        = Globe;
  GemIcon          = Gem;
  SettingsIcon     = Settings;
  UserCircleIcon   = UserCircle;
  ChevronRightIcon = ChevronRight;
  ServerIcon       = Server;
  FolderSearchIcon = FolderSearch;
  BotIcon          = Bot;
  CpuIcon          = Cpu;
  PlusIcon         = Plus;
  AlertCircleIcon  = AlertCircle;
  XCircleIcon      = XCircle;
  ChevronDownIcon  = ChevronDown;
  CheckIcon        = Check;

  // ── Signals ──────────────────────────────────────────────────────────────

  readonly sensorKeys          = signal<SensorKey[]>([]);
  readonly sensorAssignments   = signal<SensorAssignment[]>([]);
  readonly sensorAssignLoading = signal(false);
  readonly sensorAssignSaving  = signal(false);
  readonly pendingSensorSel    = signal<Record<string, string[]>>({});
  readonly sensorDropdownOpen  = signal<Record<string, boolean>>({});
  readonly activeSectionTab    = signal<'users' | 'sensors'>('users');
  readonly selectedUserIds     = signal(new Set<string>());
  readonly roleChartData       = signal<any>({ labels: [], datasets: [] });
  readonly statusChartData     = signal<any>({ labels: [], datasets: [] });
  readonly searchTerm          = signal('');
  readonly sortField           = signal<keyof TenantUser | 'status'>('username');
  readonly sortAscending       = signal(true);
  readonly users               = signal<TenantUser[]>([]);
  readonly loading             = signal(false);
  readonly saving              = signal(false);
  readonly showForm            = signal(false);
  readonly editingUser         = signal<TenantUser | null>(null);
  readonly message             = signal('');
  readonly messageType         = signal<'success' | 'error'>('success');
  readonly usernameStatus      = signal<'idle' | 'checking' | 'available' | 'taken' | 'unavailable'>('idle');
  readonly usernameTouched     = signal(false);
  readonly passwordTouched     = signal(false);

  // ── Computed ──────────────────────────────────────────────────────────────

  readonly activeUsers     = computed(() => this.users().filter(u => u.active !== false).length);
  readonly analystUsers    = computed(() => this.users().filter(u => u.role === 'analyst' || u.role === 'senior_analyst').length);
  readonly viewerUsers     = computed(() => this.users().filter(u => u.role === 'viewer').length);
  readonly assignableUsers = computed(() => this.users());

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

  // ── Form state ────────────────────────────────────────────────────────────

  userForm = {
    username: '',
    password: '',
    role: 'analyst',
    active: true,
    permissions: ['dashboard', 'health'] as string[],
  };

  // ── Constants ─────────────────────────────────────────────────────────────

  readonly donutChartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '78%',
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#0C1220', titleColor: '#EFF6FF', bodyColor: '#94A3B8',
        borderColor: 'rgba(255,255,255,0.10)', borderWidth: 1, padding: 14,
        cornerRadius: 10, displayColors: true, boxWidth: 8, boxHeight: 8,
      }
    },
    elements: { arc: { borderWidth: 4, borderColor: '#0B1120', borderRadius: 4, hoverOffset: 6 } }
  };

  readonly permissionOptions: PermissionOption[] = [
    // NDR pages
    { key: 'dashboard',    label: 'Dashboard',       description: 'Operational overview',         icon: LayoutDashboard },
    { key: 'alerts',       label: 'Alerts',           description: 'Alert triage',                icon: Bell,            requiredFeatures: ['ndr', 'soar'] },
    { key: 'assets',       label: 'Assets',           description: 'Asset inventory',             icon: Server,          requiredFeatures: ['ndr', 'soar'] },
    { key: 'logs',         label: 'Network Logs',     description: 'Event records',               icon: FileText,        requiredFeatures: ['ndr'] },
    { key: 'live',         label: 'Live Stream',      description: 'Real-time activity',          icon: Radio,           requiredFeatures: ['ndr'] },
    { key: 'network-map',  label: 'Network Map',      description: 'Topology view',               icon: Network,         requiredFeatures: ['ndr'] },
    { key: 'intel',        label: 'Threat Intel',     description: 'IOC lookup',                  icon: Globe,           requiredFeatures: ['threat_intel'] },
    { key: 'health',       label: 'System Health',    description: 'Service status',              icon: Activity,        requiredFeatures: ['ndr'] },
    { key: 'rules',        label: 'Rules View',       description: 'Detection rules',             icon: Gem,             requiredFeatures: ['ndr'] },
    { key: 'evidence',     label: 'Evidence',         description: 'Artifact locker',             icon: FolderSearch,    requiredFeatures: ['ndr'] },
    { key: 'honeypots',    label: 'Honeypots',        description: 'Deception trap management',   icon: Shield,          requiredFeatures: ['ndr'] },
    { key: 'retrospective',label: 'Retrospective',    description: 'Historical rule re-scan',     icon: RotateCcw,       requiredFeatures: ['ndr'] },
    { key: 'soar',         label: 'SOAR View',        description: 'Automation visibility',       icon: Settings,        requiredFeatures: ['soar'] },
    { key: 'ai-activity',  label: 'AI Activity',      description: 'Aria interactions',           icon: Bot,             requiredFeatures: ['ai'] },
    { key: 'ai-report',    label: 'AI Report',        description: 'AI-generated reports',        icon: Bot,             requiredFeatures: ['ai'] },
    // SIEM pages
    { key: 'siem-dashboard', label: 'SIEM Dashboard', description: 'Security events overview',   icon: ShieldAlert,     requiredFeatures: ['siem'] },
    { key: 'siem-logs',      label: 'SIEM Logs',      description: 'Ingested log stream',         icon: ScrollText,      requiredFeatures: ['siem'] },
    { key: 'siem-sources',   label: 'SIEM Sources',   description: 'Log source management',       icon: Database,        requiredFeatures: ['siem'] },
  ];

  private readonly allPermissionCategories = [
    { title: 'CORE',       keys: ['dashboard', 'alerts', 'assets'] },
    { title: 'NETWORK',    keys: ['logs', 'network-map', 'live'] },
    { title: 'SECURITY',   keys: ['intel', 'rules', 'evidence'] },
    { title: 'ENFORCE',    keys: ['honeypots', 'retrospective'] },
    { title: 'OPERATIONS', keys: ['health', 'soar', 'ai-activity', 'ai-report'] },
    { title: 'SIEM',       keys: ['siem-dashboard', 'siem-logs', 'siem-sources'] },
  ];

  // ── License-aware permission computed signals ──────────────────────────────
  // Using computed() so these only recompute when _tenantFeatures changes,
  // not on every change-detection cycle like a plain getter would.

  readonly permissionCategories = computed(() => {
    const feats = this._tenantFeatures();
    const licensed = this.permissionOptions.filter(p => {
      if (!p.requiredFeatures || p.requiredFeatures.length === 0) return true;
      // OR logic: page is accessible if tenant has ANY of the required features
      return p.requiredFeatures.some(f => feats.includes(f));
    });
    return this.allPermissionCategories
      .map(cat => ({
        title: cat.title,
        options: cat.keys.map(k => licensed.find(p => p.key === k)!).filter(Boolean),
      }))
      .filter(cat => cat.options.length > 0);
  });

  readonly roleOptions = [
    { value: 'analyst',        label: 'Analyst',        tier: 'blue' },
    { value: 'senior_analyst', label: 'Senior Analyst', tier: 'violet' },
    { value: 'viewer',         label: 'Viewer',         tier: 'slate' },
  ];

  // ── Private internals ─────────────────────────────────────────────────────

  private usernameTimer: ReturnType<typeof setTimeout> | null = null;
  private usernameCheckSub: Subscription | null = null;
  private messageTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly usernamePattern = /^[A-Za-z0-9._-]+$/;
  private permLabelsCache = new Map<string, string[]>();
  // Lazy document click listener — only attached while a sensor dropdown is open
  private docClickListener: (() => void) | null = null;

  trackByUserId(_: number, user: TenantUser) { return user.id; }
  trackByIndex(i: number)                    { return i; }

  constructor(private api: Api, private auth: AuthService) {}

  ngOnInit() {
    if (!this.tenantId) {
      const user = this.auth.getUser();
      this.tenantId = user?.tenant_id || 'default';
      if (!this.tenantName || this.tenantName === 'Organization') {
        this.tenantName = (this.tenantId.split(/[-_]/).filter(Boolean)
          .map((p: string) => p.charAt(0).toUpperCase() + p.slice(1)).join(' ')) || 'Organization';
      }
    }
    // @Input() tenantFeatures is bound by the parent (TenantAdmin) which already
    // fetches the live value. Only seed from JWT here as a fallback for cases where
    // this component is loaded as a standalone route without a parent binding.
    if (!this._tenantFeatures().length) {
      const jwtFeats = this.auth.getTenantFeatures();
      this._tenantFeatures.set(jwtFeats.length ? jwtFeats : ['ndr']);
    }
    this.loadUsers();
    this.loadSensorData();
  }

  ngOnDestroy() {
    this.clearUsernameCheck();
    this.removeDocClickListener();
    if (this.messageTimer) clearTimeout(this.messageTimer);
  }

  // ── Getters ───────────────────────────────────────────────────────────────

  get usernameError() { return this.validateUsername(this.userForm.username); }

  get usernameFeedback() {
    const status = this.usernameStatus();
    if (this.editingUser() || this.usernameError) return '';
    if (status === 'checking')    return 'Checking username availability...';
    if (status === 'available')   return 'Username is available';
    if (status === 'taken')       return 'Username already exists';
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

  passwordStrength(): number {
    const p = this.userForm.password || '';
    let score = 0;
    if (p.length >= 8) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[0-9]/.test(p)) score++;
    if (/[!@#$%^&*()\-_=+\[\]{}|;':",.\/<>?]/.test(p)) score++;
    return score;
  }

  passwordStrengthLabel(): string { return (['', 'Weak', 'Fair', 'Good', 'Strong'])[this.passwordStrength()] || ''; }
  passwordStrengthColor(): string { return (['', '#ef4444', '#f59e0b', '#3b82f6', '#22c55e'])[this.passwordStrength()] || ''; }

  get canSaveUser() {
    return (
      !this.saving() && !this.usernameError &&
      this.passwordErrors.length === 0 &&
      (this.editingUser() || this.usernameStatus() === 'available')
    );
  }

  // ── Users ─────────────────────────────────────────────────────────────────

  loadUsers() {
    this.loading.set(true);
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.permLabelsCache.clear();
        const tid = this.tenantId;
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
    const tid = this.tenantId;

    // Skip the getSensorKeys request if the parent shell already provided them
    // via @Input() parentSensorKeys (populated during its status poll forkJoin).
    if (!this.sensorKeys().length) {
      this.api.getSensorKeys().subscribe({
        next: (keys) => {
          this.sensorKeys.set(keys.filter(k => k.tenant_id === tid && k.active !== false));
        },
        error: () => {}
      });
    }

    this.api.getSensorAssignments().subscribe({
      next: (res) => {
        this.sensorAssignments.set(res.assignments || []);
        this.sensorAssignLoading.set(false);
      },
      error: () => { this.sensorAssignLoading.set(false); }
    });
  }

  getUserSensorIds(userId: string): string[] {
    return this.sensorAssignments().filter(a => a.user_id === userId).map(a => a.sensor_id);
  }

  getSensorLabel(prefix: string): string {
    const s = this.sensorKeys().find(k => k.key_prefix === prefix);
    return s ? (s.name || s.key_prefix) : prefix;
  }

  getAvailableSensors(userId: string): SensorKey[] {
    const assigned = new Set(this.getUserSensorIds(userId));
    return this.sensorKeys().filter(k => !assigned.has(k.key_prefix));
  }

  private addDocClickListener() {
    if (this.docClickListener) return; // already attached
    this.docClickListener = () => {
      const open = this.sensorDropdownOpen();
      if (Object.keys(open).some(k => open[k])) this.sensorDropdownOpen.set({});
      this.removeDocClickListener();
    };
    document.addEventListener('click', this.docClickListener);
  }

  private removeDocClickListener() {
    if (this.docClickListener) {
      document.removeEventListener('click', this.docClickListener);
      this.docClickListener = null;
    }
  }

  toggleSensorDropdown(userId: string, event: Event) {
    event.stopPropagation();
    const wasOpen = !!this.sensorDropdownOpen()[userId];
    if (wasOpen) {
      this.sensorDropdownOpen.set({});
      this.removeDocClickListener();
    } else {
      this.sensorDropdownOpen.set({ [userId]: true });
      this.addDocClickListener();
    }
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
    let done = 0, errors = 0;

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
        this.showMessage('Sensor removed. Analyst must log out and back in.', 'success');
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
      username: '', password: '', role: 'analyst', active: true,
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
      username: user.username, password: '', role: user.role,
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
    if (this.editingUser() || this.usernameError) { this.usernameStatus.set('idle'); return; }
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
    if (validationError) { this.showMessage(validationError, 'error'); return; }

    const editing = this.editingUser();
    if (editing) {
      this.saving.set(true);
      const permissions = this.normalizePermissions(this.userForm.permissions, this.userForm.role);
      const userId      = editing.id;
      const wasActive   = editing.active !== false;
      const nowActive   = this.userForm.active;
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
                next: (sd: any) => {
                  if (sd.status === 'ok') {
                    this.afterSaveComplete(userId, permissions, nowActive);
                  } else {
                    this.saving.set(false);
                    this.showMessage(sd.message || 'Permissions saved but failed to update status', 'error');
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
              next: (pd: any) => {
                if (pd.status === 'ok') { afterPermissions(); }
                else {
                  this.saving.set(false);
                  this.showMessage(pd.message || 'Access updated, but failed to reset password', 'error');
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

    this.saving.set(true);
    const permissions = this.normalizePermissions(this.userForm.permissions, this.userForm.role);
    this.api.createUser({
      username: this.userForm.username.trim(),
      password: this.userForm.password,
      role: this.userForm.role,
      tenant_id: this.tenantId,
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
      error: () => { this.saving.set(false); this.showMessage('Failed to create user', 'error'); },
    });
  }

  private afterSaveComplete(userId: string, permissions: string[], active: boolean) {
    this.saving.set(false);
    this.users.update(list => list.map(u => u.id === userId ? { ...u, permissions, active } : u));
    this.updateCharts();
    this.closeForm();
    this.showMessage(active ? 'User updated successfully' : 'User disabled successfully', 'success');
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
    if (selected.has(permission)) selected.delete(permission); else selected.add(permission);
    this.userForm.permissions = Array.from(selected);
  }

  hasPermission(permission: string) { return this.userForm.permissions.includes(permission); }

  onRoleChange() {
    if (!this.editingUser()) this.userForm.permissions = this.defaultPermissionsFor(this.userForm.role);
  }

  selectRole(value: string) {
    if (this.editingUser()) return;
    this.userForm.role = value;
    this.onRoleChange();
  }

  getUserStatus(user: TenantUser): 'active' | 'disabled' { return user.active !== false ? 'active' : 'disabled'; }
  getRoleLabel(role: string) { return this.roleOptions.find(o => o.value === role)?.label || role; }

  getPermissionLabels(user: TenantUser): string[] {
    const hit = this.permLabelsCache.get(user.id);
    if (hit) return hit;
    const permissions = this.normalizePermissions(user.permissions, user.role);
    const labels = this.permissionOptions.filter(o => permissions.includes(o.key)).map(o => o.label);
    this.permLabelsCache.set(user.id, labels);
    return labels;
  }

  toggleSort(field: keyof TenantUser | 'status') {
    if (this.sortField() === field) this.sortAscending.update(v => !v);
    else { this.sortField.set(field); this.sortAscending.set(true); }
  }

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
      if (visible.length > 0 && visible.every(u => s.has(u.id))) return new Set<string>();
      return new Set(visible.map(u => u.id));
    });
  }

  isAllSelected(): boolean {
    const visible = this.filteredAndSortedUsers();
    return visible.length > 0 && visible.every(u => this.selectedUserIds().has(u.id));
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
          if (completed === total) { this.saving.set(false); this.loadUsers(); }
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
    const csv = [headers.join(','), ...data.map(row => headers.map(h => `"${(row as any)[h]}"`).join(','))].join('\n');
    const blob      = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const objectUrl = URL.createObjectURL(blob);
    const link      = document.createElement('a');
    link.setAttribute('href', objectUrl);
    link.setAttribute('download', `tenant_users_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(objectUrl);
  }

  showMessage(message: string, type: 'success' | 'error') {
    this.message.set(message);
    this.messageType.set(type);
    if (this.messageTimer) clearTimeout(this.messageTimer);
    this.messageTimer = setTimeout(() => { this.message.set(''); this.messageTimer = null; }, 5000);
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private updateCharts() {
    const list     = this.users();
    const analyst  = list.filter(u => u.role === 'analyst').length;
    const senior   = list.filter(u => u.role === 'senior_analyst').length;
    const viewer   = list.filter(u => u.role === 'viewer').length;
    this.roleChartData.set({
      labels: ['Analyst', 'Senior Analyst', 'Viewer'],
      datasets: [{ data: [analyst, senior, viewer], backgroundColor: ['#0EA5E9', '#8B5CF6', '#10B981'], hoverBackgroundColor: ['#38BDF8', '#A78BFA', '#34D399'], borderWidth: 4, borderColor: '#0B1120', hoverOffset: 6 }]
    });
    const active   = this.activeUsers();
    const disabled = list.length - active;
    this.statusChartData.set({
      labels: ['Active', 'Disabled'],
      datasets: [{ data: [active, disabled], backgroundColor: ['#10B981', '#475569'], hoverBackgroundColor: ['#34D399', '#64748B'], borderWidth: 4, borderColor: '#0B1120', hoverOffset: 6 }]
    });
  }

  // ── License-aware permission helpers ──────────────────────────────────────

  readonly licensedPermissionOptions = computed(() =>
    this.permissionCategories().flatMap(c => c.options)
  );

  readonly licensedPermissionCategories = computed(() =>
    this.permissionCategories()
  );

  readonly visibleEnabledCount = computed(() => {
    const licensed = new Set(this.licensedPermissionOptions().map(p => p.key));
    return this.userForm.permissions.filter(p => licensed.has(p)).length;
  });

  private defaultPermissionsFor(role: string): string[] {
    const licensed = this.licensedPermissionOptions().map(p => p.key);
    if (role === 'viewer')         return ['dashboard', 'health'].filter(k => licensed.includes(k));
    if (role === 'senior_analyst') return licensed;
    // analyst: dashboard + everything except enforce pages (honeypots/retrospective)
    const enforce = new Set(['honeypots', 'retrospective']);
    return licensed.filter(k => !enforce.has(k));
  }

  private normalizePermissions(value: unknown, role: string): string[] {
    const permissions = Array.isArray(value)
      ? value
      : typeof value === 'string' ? value.split(',') : this.defaultPermissionsFor(role);
    return Array.from(new Set(
      permissions.map(p => String(p).trim()).filter(Boolean)
        .map(p => p.endsWith(':view') ? p.replace(':view', '') : p)
        .map(p => p === 'network' ? 'network-map' : p)
    ));
  }

  private isManageableTenantUser(user: TenantUser) {
    if (['admin', 'super_admin', 'tenant_admin'].includes(user.role)) return false;
    const me = this.auth.getUser();
    return user.id !== me?.id && user.username !== me?.username;
  }

  private firstValidationError() {
    const status = this.usernameStatus();
    if (this.usernameError) return this.usernameError;
    if (!this.editingUser() && status === 'checking')    return 'Wait for username availability check';
    if (!this.editingUser() && status === 'taken')       return 'Username already exists';
    if (!this.editingUser() && status === 'unavailable') return 'Could not check username availability';
    if (!this.editingUser() && status !== 'available')   return 'Confirm username availability';
    return this.passwordErrors[0] || '';
  }

  private validateUsername(username: string) {
    const value = username.trim();
    if (!value) return 'Username is required';
    if (value.length < 3) return 'Username must be at least 3 characters';
    if (value.length > 50) return 'Username must be 50 characters or less';
    if (!this.usernamePattern.test(value)) return 'Username can use letters, numbers, dot, underscore, and hyphen only';
    if (!this.editingUser() && this.users().some(u => u.username?.trim().toLowerCase() === value.toLowerCase())) return 'Username already exists';
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
    if (username.trim() && value.toLowerCase() === username.trim().toLowerCase()) errors.push('Password cannot be the same as username');
    return errors;
  }

  private clearUsernameCheck() {
    if (this.usernameTimer) { clearTimeout(this.usernameTimer); this.usernameTimer = null; }
    this.usernameCheckSub?.unsubscribe();
    this.usernameCheckSub = null;
    this.usernameStatus.set('idle');
  }
}
