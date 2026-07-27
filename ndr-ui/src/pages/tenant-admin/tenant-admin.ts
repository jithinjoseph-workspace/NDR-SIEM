import { Component, OnInit, OnDestroy, ChangeDetectorRef, HostListener } from '@angular/core';
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
  Check
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

  // Sensor Assignment
  sensorKeys: SensorKey[] = [];
  sensorAssignments: SensorAssignment[] = [];
  sensorAssignLoading = false;
  sensorAssignSaving = false;
  /** Per-user multi-selected sensor key_prefixes pending assignment */
  pendingSensorSel: Record<string, string[]> = {};
  /** Tracks which user's sensor dropdown is open */
  sensorDropdownOpen: Record<string, boolean> = {};
  activeSectionTab: 'users' | 'sensors' = 'users';

  // Bulk Selection
  selectedUserIds: Set<string> = new Set();

  activeTab: 'users' | 'trusted-domains' = 'users';

  // Trusted Domains (tenant-specific)
  trustedDomains: any[] = [];
  loadingTrustedDomains = false;
  tdNewDomain = '';
  tdNewCategory = 'dns_beacon';
  tdNewNote = '';
  tdSaving = false;
  tdAiLoading = false;
  tdAiAvailable: boolean | null = null;
  tdAiSuggestions: any[] = [];
  
  // Data Grid specific
  searchTerm = '';
  sortField: keyof TenantUser | 'status' = 'username';
  sortAscending = true;

  // Chart Data Configurations
  public roleChartData: any = { labels: [], datasets: [] };
  public statusChartData: any = { labels: [], datasets: [] };

  public donutChartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '78%',
    plugins: {
      legend: {
        display: false
      },
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
      arc: { 
        borderWidth: 4, 
        borderColor: '#0B1120',
        borderRadius: 4,
        hoverOffset: 6 
      }
    }
  };

  tenantSystemStatus: 'OPERATIONAL' | 'DEGRADED' | 'CHECKING...' = 'CHECKING...';
  private statusInterval: ReturnType<typeof setInterval> | null = null;

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
  usernameTouched = false;
  passwordTouched = false;
  private usernameTimer: ReturnType<typeof setTimeout> | null = null;
  private usernameCheckSub: Subscription | null = null;
  private readonly usernamePattern = /^[A-Za-z0-9._-]+$/;

  permissionOptions: PermissionOption[] = [
    { key: 'dashboard', label: 'Dashboard', description: 'Operational overview and key metrics', icon: this.LayoutDashboardIcon },
    { key: 'alerts', label: 'Alerts', description: 'Correlation hits and alert triage', icon: this.BellIcon },
    { key: 'assets', label: 'Assets', description: 'Asset inventory and tracking', icon: this.ServerIcon },
    { key: 'logs', label: 'Network Logs', description: 'Agent-Z and Agent-S event records', icon: this.FileTextIcon },
    { key: 'live', label: 'Live Stream', description: 'Real-time network activity', icon: this.RadioIcon },
    { key: 'network-map', label: 'Network Map', description: 'Source and destination topology', icon: this.NetworkIcon },
    { key: 'intel', label: 'Threat Intel', description: 'IOC lookup and enrichment', icon: this.GlobeIcon },
    { key: 'health', label: 'System Health', description: 'Service and sensor status', icon: this.ActivityIcon },
    { key: 'rules', label: 'Rules View', description: 'Read-only detection rule access', icon: this.GemIcon },
    { key: 'evidence', label: 'Evidence', description: 'Evidence and artifact locker', icon: this.FolderSearchIcon },
    { key: 'soar', label: 'SOAR View', description: 'Read-only automation visibility', icon: this.SettingsIcon },
    { key: 'ai-activity', label: 'AI Activity', description: 'Aria analyst interactions', icon: this.BotIcon },
    { key: 'ai-report',   label: 'AI Report',   description: 'AI-generated security reports', icon: this.BotIcon },
  ];

  permissionCategories = [
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

  roleOptions = [
    { value: 'analyst', label: 'Analyst', tier: 'blue' },
    { value: 'senior_analyst', label: 'Senior Analyst', tier: 'violet' },
    { value: 'viewer', label: 'Viewer', tier: 'slate' },
  ];

  userForm = {
    username: '',
    password: '',
    role: 'analyst',
    active: true,
    permissions: [
      'dashboard',
      'alerts',
      'assets',
      'logs',
      'live',
      'network-map',
      'intel',
      'health',
      'evidence',
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

    const allowed = ['admin', 'super_admin', 'tenant_admin'].includes(this.currentUser.role);
    if (!allowed) {
      this.router.navigate(['/dashboard']);
      return;
    }

    this.refreshTenantSystemStatus();
    this.statusInterval = setInterval(() => this.refreshTenantSystemStatus(), 10000);

    this.loadUsers();
    this.loadSensorData();
  }

  ngOnDestroy(): void {
    this.clearUsernameCheck();
    if (this.statusInterval) clearInterval(this.statusInterval);
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
        this.updateCharts();
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

  loadSensorData() {
    this.sensorAssignLoading = true;

    // Load sensor keys for this tenant
    this.api.getSensorKeys().subscribe({
      next: (keys) => {
        this.sensorKeys = keys.filter(k => k.tenant_id === this.tenantId && k.active !== false);
        this.cdr.detectChanges();
      },
      error: () => { this.cdr.detectChanges(); }
    });

    // Load assignments
    this.api.getSensorAssignments().subscribe({
      next: (res) => {
        this.sensorAssignments = res.assignments || [];
        this.sensorAssignLoading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.sensorAssignLoading = false;
        this.cdr.detectChanges();
      }
    });
  }

  /** Returns the sensor_ids assigned to a specific user */
  getUserSensorIds(userId: string): string[] {
    return this.sensorAssignments
      .filter(a => a.user_id === userId)
      .map(a => a.sensor_id);
  }

  /** Returns sensor key object by key_prefix */
  getSensorByPrefix(prefix: string): SensorKey | undefined {
    return this.sensorKeys.find(k => k.key_prefix === prefix);
  }

  /** Returns sensor name/label for display */
  getSensorLabel(prefix: string): string {
    const s = this.getSensorByPrefix(prefix);
    return s ? (s.name || s.key_prefix) : prefix;
  }

  /** Available sensors not yet assigned to this user */
  getAvailableSensors(userId: string): SensorKey[] {
    const assigned = new Set(this.getUserSensorIds(userId));
    return this.sensorKeys.filter(k => !assigned.has(k.key_prefix));
  }

  @HostListener('document:click')
  closeAllSensorDropdowns() {
    if (Object.keys(this.sensorDropdownOpen).some(k => this.sensorDropdownOpen[k])) {
      this.sensorDropdownOpen = {};
      this.cdr.detectChanges();
    }
  }

  toggleSensorDropdown(userId: string, event: Event) {
    event.stopPropagation();
    const wasOpen = !!this.sensorDropdownOpen[userId];
    this.sensorDropdownOpen = {};
    if (!wasOpen) this.sensorDropdownOpen[userId] = true;
    this.cdr.detectChanges();
  }

  isSensorSelected(userId: string, sensorId: string): boolean {
    return (this.pendingSensorSel[userId] || []).includes(sensorId);
  }

  toggleSensorSelection(userId: string, sensorId: string) {
    const current = this.pendingSensorSel[userId] || [];
    this.pendingSensorSel[userId] = current.includes(sensorId)
      ? current.filter(id => id !== sensorId)
      : [...current, sensorId];
    this.cdr.detectChanges();
  }

  getSelectedCount(userId: string): number {
    return (this.pendingSensorSel[userId] || []).length;
  }

  addSensorsToUser(userId: string) {
    const toAssign = [...(this.pendingSensorSel[userId] || [])];
    if (toAssign.length === 0) return;

    this.sensorAssignSaving = true;
    this.sensorDropdownOpen = {};
    const total = toAssign.length;
    let done = 0;
    let errors = 0;

    for (const sensorId of toAssign) {
      this.api.assignSensor(userId, sensorId).subscribe({
        next: () => {
          this.sensorAssignments = [...this.sensorAssignments, { user_id: userId, sensor_id: sensorId }];
          done++;
          if (done + errors === total) {
            this.pendingSensorSel[userId] = [];
            this.sensorAssignSaving = false;
            this.showMessage(
              errors === 0
                ? `${total} sensor(s) assigned. Analyst must re-login for changes to take effect.`
                : `${total - errors} assigned, ${errors} failed.`,
              errors === 0 ? 'success' : 'error'
            );
            this.cdr.detectChanges();
          }
        },
        error: () => {
          errors++;
          if (done + errors === total) {
            this.pendingSensorSel[userId] = [];
            this.sensorAssignSaving = false;
            this.showMessage(`${total - errors} assigned, ${errors} failed.`, 'error');
            this.cdr.detectChanges();
          }
        }
      });
    }
  }

  removeSensorFromUser(userId: string, sensorId: string) {
    this.sensorAssignSaving = true;
    this.api.unassignSensor(userId, sensorId).subscribe({
      next: () => {
        this.sensorAssignments = this.sensorAssignments.filter(
          a => !(a.user_id === userId && a.sensor_id === sensorId)
        );
        this.sensorAssignSaving = false;
        this.showMessage('Sensor removed. Analyst must log out and back in for changes to take effect.', 'success');
        this.cdr.detectChanges();
      },
      error: () => {
        this.sensorAssignSaving = false;
        this.showMessage('Failed to remove sensor assignment', 'error');
        this.cdr.detectChanges();
      }
    });
  }

  /** Users who can have sensor assignments (excludes admins/tenant_admins) */
  get assignableUsers() {
    return this.users;
  }

  openCreateForm() {
    this.clearUsernameCheck();
    this.usernameTouched = false;
    this.passwordTouched = false;
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
    this.usernameTouched = false;
    this.passwordTouched = false;
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
    this.updateCharts();
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

  selectRole(value: string) {
    if (this.editingUser) return;
    this.userForm.role = value;
    this.onRoleChange();
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

  // Enterprise Data Grid Getters
  get filteredAndSortedUsers() {
    let result = this.users;
    
    // Filter
    if (this.searchTerm) {
      const term = this.searchTerm.toLowerCase();
      result = result.filter(u => 
        u.username.toLowerCase().includes(term) || 
        this.getRoleLabel(u.role).toLowerCase().includes(term)
      );
    }
    
    // Sort
    result = [...result].sort((a, b) => {
      let valA: any = a[this.sortField as keyof TenantUser];
      let valB: any = b[this.sortField as keyof TenantUser];
      
      if (this.sortField === 'status') {
        valA = a.active ? 1 : 0;
        valB = b.active ? 1 : 0;
      }
      
      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();
      
      if (valA < valB) return this.sortAscending ? -1 : 1;
      if (valA > valB) return this.sortAscending ? 1 : -1;
      return 0;
    });
    
    return result;
  }
  
  toggleSort(field: keyof TenantUser | 'status') {
    if (this.sortField === field) {
      this.sortAscending = !this.sortAscending;
    } else {
      this.sortField = field;
      this.sortAscending = true;
    }
  }

  // Chart Generation Logic
  private updateCharts() {
    this.generateRoleChart();
    this.generateStatusChart();
  }

  private generateRoleChart() {
    const roles = {
      Analyst: 0,
      'Senior Analyst': 0,
      Viewer: 0
    };
    
    this.users.forEach(u => {
      if (u.role === 'analyst') roles.Analyst++;
      else if (u.role === 'senior_analyst') roles['Senior Analyst']++;
      else if (u.role === 'viewer') roles.Viewer++;
    });

    this.roleChartData = {
      labels: ['Analyst', 'Senior Analyst', 'Viewer'],
      datasets: [{
        data: [roles.Analyst, roles['Senior Analyst'], roles.Viewer],
        backgroundColor: ['#0EA5E9', '#8B5CF6', '#10B981'],
        hoverBackgroundColor: ['#38BDF8', '#A78BFA', '#34D399'],
        borderWidth: 4,
        borderColor: '#0B1120',
        hoverOffset: 6
      }]
    };
  }

  private generateStatusChart() {
    const active = this.activeUsers;
    const disabled = this.users.length - active;

    this.statusChartData = {
      labels: ['Active', 'Disabled'],
      datasets: [{
        data: [active, disabled],
        backgroundColor: ['#10B981', '#475569'],
        hoverBackgroundColor: ['#34D399', '#64748B'],
        borderWidth: 4,
        borderColor: '#0B1120',
        hoverOffset: 6
      }]
    };
  }

  // Bulk Actions
  toggleSelection(userId: string) {
    if (this.selectedUserIds.has(userId)) {
      this.selectedUserIds.delete(userId);
    } else {
      this.selectedUserIds.add(userId);
    }
  }

  toggleAll() {
    const visibleUsers = this.filteredAndSortedUsers;
    if (this.isAllSelected()) {
      this.selectedUserIds.clear();
    } else {
      visibleUsers.forEach(u => this.selectedUserIds.add(u.id));
    }
  }

  isAllSelected(): boolean {
    const visibleUsers = this.filteredAndSortedUsers;
    return visibleUsers.length > 0 && visibleUsers.every(u => this.selectedUserIds.has(u.id));
  }

  bulkUpdateStatus(active: boolean) {
    if (this.selectedUserIds.size === 0) return;
    const action = active ? 'enable' : 'disable';
    if (!confirm(`Are you sure you want to ${action} ${this.selectedUserIds.size} users?`)) return;

    let completed = 0;
    const total = this.selectedUserIds.size;
    this.saving = true;

    this.selectedUserIds.forEach(id => {
      this.api.setUserStatus(id, active).subscribe({
        next: () => {
          completed++;
          if (completed === total) {
            this.selectedUserIds.clear();
            this.saving = false;
            this.showMessage(`Successfully ${action}d ${total} users`, 'success');
            this.loadUsers();
          }
        },
        error: () => {
          completed++;
          if (completed === total) {
            this.saving = false;
            this.loadUsers();
          }
        }
      });
    });
  }

  exportToCSV() {
    const data = this.filteredAndSortedUsers.map(u => ({
      Username: u.username,
      Role: this.getRoleLabel(u.role),
      Status: u.active ? 'Active' : 'Disabled',
      Created: u.created_at ? new Date(u.created_at).toLocaleString() : 'Unknown',
      Permissions: this.normalizePermissions(u.permissions, u.role).join('; ')
    }));

    if (data.length === 0) {
      this.showMessage('No users to export', 'error');
      return;
    }

    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(','),
      ...data.map(row => headers.map(h => `"${(row as any)[h]}"`).join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `tenant_users_export_${new Date().getTime()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  private refreshTenantSystemStatus() {
    this.api.getSensorKeys().subscribe({
      next: (sensors: any[]) => {
        // Backend already scopes sensors to the tenant.
        const tenantSensors = sensors;
        
        let healthyPipeline = false;
        if (tenantSensors.length === 0) {
          healthyPipeline = true;
        } else {
          healthyPipeline = tenantSensors.some(sensor =>
            sensor.active !== false &&
            (this.isRunning(sensor['agent-z']) ||
             this.isRunning(sensor['agent-s']) ||
             this.isRunning(sensor.vector))
          );
        }

        this.api.getDashboardStats().subscribe({
          next: data => {
            const services = data?.services || {};
            const platformHealthy =
              this.isRunning(services.kafka) &&
              this.isRunning(services.clickhouse) &&
              this.isRunning(services.engine || 'running');

            this.tenantSystemStatus = healthyPipeline && platformHealthy ? 'OPERATIONAL' : 'DEGRADED';
            this.cdr.detectChanges();
          },
          error: () => {
            this.tenantSystemStatus = 'DEGRADED';
            this.cdr.detectChanges();
          },
        });
      },
      error: () => {
        this.tenantSystemStatus = 'DEGRADED';
        this.cdr.detectChanges();
      },
    });
  }

  private isRunning(status: unknown) {
    const value = String(status || '').toLowerCase().trim();
    if (['running', 'healthy', 'ok', 'up', 'active', 'started', 'unknown'].includes(value)) return true;
    return /^\d+$/.test(value);
  }

  private isRecentlySeen(value: string | undefined) {
    if (!value) return false;
    const normalized = value.includes('T') ? value : value.replace(' ', 'T');
    const withTimezone = /Z$|[+-]\d{2}:\d{2}$/.test(normalized)
      ? normalized
      : `${normalized}Z`;
    const timestamp = new Date(withTimezone).getTime();
    return !Number.isNaN(timestamp) && Date.now() - timestamp <= 2 * 60 * 1000;
  }

  // ── Trusted Domains ────────────────────────────────────────────────────────

  loadTrustedDomains() {
    this.loadingTrustedDomains = true;
    this.api.listTrustedDomains().subscribe({
      next: (data: any) => {
        this.trustedDomains = data.domains || [];
        this.loadingTrustedDomains = false;
      },
      error: () => { this.loadingTrustedDomains = false; },
    });
  }

  addTrustedDomain() {
    const d = this.tdNewDomain.trim().toLowerCase();
    if (!d) return;
    this.tdSaving = true;
    // tenant_admin: tenant_id is set server-side from JWT, pass '' to use own tenant
    this.api.addTrustedDomain(d, this.tdNewCategory, 'own', this.tdNewNote).subscribe({
      next: () => {
        this.tdNewDomain = '';
        this.tdNewNote = '';
        this.tdSaving = false;
        this.loadTrustedDomains();
      },
      error: () => { this.tdSaving = false; },
    });
  }

  deleteTenantTrustedDomain(domain: string, tenantId: string) {
    this.api.deleteTrustedDomain(domain, tenantId).subscribe({
      next: () => {
        this.trustedDomains = this.trustedDomains.filter(
          d => !(d.domain === domain && d.tenant_id === tenantId)
        );
      },
      error: () => {},
    });
  }

  runAiSuggest() {
    this.tdAiLoading = true;
    this.tdAiSuggestions = [];
    this.api.aiSuggestTrustedDomains().subscribe({
      next: (data: any) => {
        this.tdAiAvailable = data.ai_available !== false;
        this.tdAiSuggestions = (data.suggestions || []).filter((s: any) => s.verdict === 'TRUSTED');
        this.tdAiLoading = false;
      },
      error: () => { this.tdAiLoading = false; },
    });
  }

  approveTdSuggestion(s: any) {
    this.api.addTrustedDomain(s.domain, 'dns_beacon', 'own', s.reason || '').subscribe({
      next: () => {
        this.tdAiSuggestions = this.tdAiSuggestions.filter(x => x.domain !== s.domain);
        this.loadTrustedDomains();
      },
      error: () => {},
    });
  }

  dismissTdSuggestion(domain: string) {
    this.tdAiSuggestions = this.tdAiSuggestions.filter(s => s.domain !== domain);
  }

  switchTab(tab: 'users' | 'trusted-domains') {
    this.activeTab = tab;
    if (tab === 'trusted-domains') this.loadTrustedDomains();
  }

  get tenantOwnDomains() { return this.trustedDomains.filter(d => d.scope === 'tenant'); }
  get globalDomains() { return this.trustedDomains.filter(d => d.scope === 'global'); }
}
