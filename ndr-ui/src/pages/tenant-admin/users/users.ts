import {
  Component, Input, OnInit, OnDestroy, AfterViewInit, ChangeDetectionStrategy,
  signal, computed, ViewEncapsulation, ElementRef, ViewChild
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
  Database, ShieldAlert, ScrollText, Zap, Layers, Sparkles, TrendingUp
} from 'lucide-angular';
import { Api, SensorKey, SensorAssignment } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { Subscription } from 'rxjs';
import { BaseChartDirective } from 'ng2-charts';
import * as THREE from 'three';

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
export class UsersSection implements OnInit, OnDestroy, AfterViewInit {
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
  ZapIcon          = Zap;
  RotateCcwIcon    = RotateCcw;
  LayersIcon       = Layers;
  SparklesIcon     = Sparkles;
  TrendingUpIcon   = TrendingUp;

  // ── Three.js Viewport Reference ───────────────────────────────────────────
  @ViewChild('threeCanvasContainer', { static: false }) threeCanvasRef?: ElementRef<HTMLDivElement>;
  private threeRenderer?: THREE.WebGLRenderer;
  private threeScene?: THREE.Scene;
  private threeCamera?: THREE.PerspectiveCamera;
  private threeAnimId?: number;
  private threeResizeObs?: ResizeObserver;
  private threeMeshGroup?: THREE.Group;
  private icoMesh?: THREE.Mesh;
  private coreMesh?: THREE.Mesh;
  private ring1?: THREE.Mesh;
  private ring2?: THREE.Mesh;
  private points?: THREE.Points;
  private pulseRing?: THREE.Mesh;
  private pulseScale = 0;
  private pulseOpacity = 0;
  private isPointerDown = false;
  private prevPointerX = 0;
  private prevPointerY = 0;

  // ── High-Tech Cockpit & 3D Signals ─────────────────────────────────────────
  readonly threeVisualMode        = signal<'full' | 'wireframe' | 'particles' | 'core'>('full');
  readonly threeSpeed             = signal<number>(1);
  readonly authTimeframe          = signal<'6h' | '12h' | '24h' | '7d'>('24h');
  readonly feedFilter             = signal<'all' | 'auth' | 'sensor' | 'policy'>('all');

  // Real events only — pushed by pushLiveEvent() whenever an actual action
  // succeeds on this page (user created/updated/deleted, sensor assigned).
  // No seeded/simulated entries: an empty feed means nothing has happened
  // yet in this session, not that we don't have data to show.
  readonly liveAuditEvents = signal<any[]>([]);

  readonly filteredAuditEvents = computed(() => {
    const f = this.feedFilter();
    if (f === 'all') return this.liveAuditEvents();
    return this.liveAuditEvents().filter(e => e.type === f);
  });

  // ── Core Signals ──────────────────────────────────────────────────────────
  readonly sensorKeys             = signal<SensorKey[]>([]);
  readonly sensorAssignments      = signal<SensorAssignment[]>([]);
  readonly sensorAssignLoading    = signal(false);
  readonly sensorAssignSaving     = signal(false);
  readonly pendingSensorSel       = signal<Record<string, string[]>>({});
  readonly sensorDropdownOpen     = signal<Record<string, boolean>>({});
  readonly activeSectionTab       = signal<'users' | 'sensors'>('users');
  readonly selectedUserIds        = signal(new Set<string>());
  readonly roleChartData          = signal<any>({ labels: [], datasets: [] });
  readonly statusChartData        = signal<any>({ labels: [], datasets: [] });
  readonly authTimelineChartData  = signal<any>({ labels: [], datasets: [] });
  readonly clearanceBarChartData  = signal<any>({ labels: [], datasets: [] });
  readonly searchTerm             = signal('');
  readonly sortField              = signal<keyof TenantUser | 'status'>('username');
  readonly sortAscending          = signal(true);
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

  // Real ingestion telemetry for this tenant — see loadIngestStats().
  readonly ingestEventsTotal   = signal(0);
  readonly ingestEvents1h      = signal(0);
  readonly ingestHits1h        = signal(0);

  // ── Computed ──────────────────────────────────────────────────────────────

  readonly activeUsers        = computed(() => this.users().filter(u => u.active !== false).length);
  readonly analystUsers       = computed(() => this.users().filter(u => u.role === 'analyst' || u.role === 'senior_analyst').length);
  // 'analyst' role only — matches the donut chart's own "Analyst" segment,
  // which is computed separately in updateCharts() and does NOT include
  // senior_analyst (unlike analystUsers() above, kept for the seat bar).
  readonly pureAnalystUsers   = computed(() => this.users().filter(u => u.role === 'analyst').length);
  readonly seniorAnalystUsers = computed(() => this.users().filter(u => u.role === 'senior_analyst').length);
  readonly viewerUsers        = computed(() => this.users().filter(u => u.role === 'viewer').length);
  readonly assignableUsers    = computed(() => this.users());
  readonly accountHealthPct   = computed(() => {
    const total = this.users().length;
    return total > 0 ? Math.round((this.activeUsers() / total) * 100) : 100;
  });
  readonly suspendedUsers     = computed(() => this.users().length - this.activeUsers());
  readonly onlineSensorCount  = computed(() => this.sensorKeys().filter(s => s.active).length);
  readonly totalSensorCount   = computed(() => this.sensorKeys().length);
  // One segment per real account — no fabricated seat cap.
  readonly seatBarSlots       = computed(() => Array.from({ length: Math.max(this.users().length, 1) }, (_, i) => i));

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
    cutout: '76%',
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#101426', titleColor: '#ffffff', bodyColor: '#8a94b2',
        borderColor: 'rgba(255,255,255,0.08)', borderWidth: 1, padding: 12,
        cornerRadius: 8, displayColors: true, boxWidth: 8, boxHeight: 8,
      }
    },
    elements: { arc: { borderWidth: 4, borderColor: '#171b37', borderRadius: 4, hoverOffset: 6 } }
  };

  readonly lineChartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#101426', titleColor: '#ffffff', bodyColor: '#8a94b2',
        borderColor: 'rgba(255,255,255,0.08)', borderWidth: 1, padding: 12, cornerRadius: 8
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(255, 255, 255, 0.04)', drawBorder: false },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.04)', drawBorder: false },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, precision: 0 }
      }
    },
    elements: {
      line: { tension: 0.38, borderWidth: 3 },
      point: { radius: 3, hoverRadius: 6 }
    }
  };

  readonly barChartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#101426', titleColor: '#ffffff', bodyColor: '#8a94b2',
        borderColor: 'rgba(255,255,255,0.08)', borderWidth: 1, padding: 12, cornerRadius: 8
      }
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#64748b', font: { family: 'Inter', size: 10.5 } }
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.04)', drawBorder: false },
        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, precision: 0 }
      }
    }
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
    this.loadIngestStats();
  }

  loadIngestStats() {
    this.api.getStats().subscribe({
      next: (stats: any) => {
        this.ingestEventsTotal.set(Number(stats?.events_total) || 0);
        this.ingestEvents1h.set(Number(stats?.events_1h) || 0);
        this.ingestHits1h.set(Number(stats?.hits_1h) || 0);
      },
      error: () => {},
    });
  }

  ngAfterViewInit() {
    setTimeout(() => this.initThreeCyberTopology(), 80);
  }

  ngOnDestroy() {
    this.clearUsernameCheck();
    this.removeDocClickListener();
    if (this.messageTimer) clearTimeout(this.messageTimer);
    if (this.threeAnimId) cancelAnimationFrame(this.threeAnimId);
    if (this.threeResizeObs) this.threeResizeObs.disconnect();
    if (this.threeRenderer) {
      this.threeRenderer.dispose();
      this.threeRenderer.forceContextLoss();
    }
  }

  resetThreeCamera() {
    if (this.threeMeshGroup) {
      this.threeMeshGroup.rotation.set(0.25, 0, 0);
    }
  }

  setThreeMode(mode: 'full' | 'wireframe' | 'particles' | 'core') {
    this.threeVisualMode.set(mode);
    if (!this.icoMesh || !this.points || !this.coreMesh || !this.ring1 || !this.ring2) return;
    if (mode === 'full') {
      this.icoMesh.visible = true;
      this.points.visible = true;
      this.coreMesh.visible = true;
      this.ring1.visible = true;
      this.ring2.visible = true;
    } else if (mode === 'wireframe') {
      this.icoMesh.visible = true;
      this.points.visible = false;
      this.coreMesh.visible = true;
      this.ring1.visible = true;
      this.ring2.visible = true;
    } else if (mode === 'particles') {
      this.icoMesh.visible = false;
      this.points.visible = true;
      this.coreMesh.visible = true;
      this.ring1.visible = false;
      this.ring2.visible = false;
    } else if (mode === 'core') {
      this.icoMesh.visible = false;
      this.points.visible = false;
      this.coreMesh.visible = true;
      this.ring1.visible = true;
      this.ring2.visible = true;
    }
  }

  setThreeSpeed(spd: number) {
    this.threeSpeed.set(spd);
  }

  triggerPulseWave() {
    this.pulseScale = 0.5;
    this.pulseOpacity = 0.95;
  }

  setFeedFilter(filter: 'all' | 'auth' | 'sensor' | 'policy') {
    this.feedFilter.set(filter);
  }

  /** Records a real thing that just happened — never fabricated. */
  private pushLiveEvent(type: 'auth' | 'sensor' | 'policy', title: string, subtitle: string, badge: string, badgeClass: string) {
    const newEvent = { id: Date.now(), type, title, subtitle, badge, badgeClass, time: 'Just now' };
    this.liveAuditEvents.update(list => [newEvent, ...list.slice(0, 9)]);
    this.triggerPulseWave();
  }

  setAuthTimeframe(tf: '6h' | '12h' | '24h' | '7d') {
    this.authTimeframe.set(tf);
    this.updateCharts();
  }

  switchTab(tab: 'users' | 'sensors') {
    this.activeSectionTab.set(tab);
    if (tab === 'users') {
      setTimeout(() => this.initThreeCyberTopology(), 60);
    }
  }

  private initThreeCyberTopology() {
    const host = this.threeCanvasRef?.nativeElement;
    if (!host) return;
    if (this.threeRenderer) {
      this.resizeThree();
      return;
    }

    try {
      const scene = new THREE.Scene();
      this.threeScene = scene;

      const rect = host.getBoundingClientRect();
      const w = Math.max(rect.width, 320);
      const h = Math.max(rect.height, 240);

      const camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 100);
      camera.position.set(0, 0, 8.5);
      this.threeCamera = camera;

      const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
      renderer.setSize(w, h, false);
      renderer.setClearColor(0x000000, 0);
      renderer.domElement.style.width = '100%';
      renderer.domElement.style.height = '100%';
      renderer.domElement.style.display = 'block';
      host.appendChild(renderer.domElement);
      this.threeRenderer = renderer;

      const group = new THREE.Group();
      this.threeMeshGroup = group;
      group.rotation.set(0.25, 0, 0);
      scene.add(group);

      // 1. Outer wireframe nodal icosahedron (Electric Cyan)
      const icoGeo = new THREE.IcosahedronGeometry(2.3, 1);
      const icoMat = new THREE.MeshBasicMaterial({
        color: 0x00f2fe,
        wireframe: true,
        transparent: true,
        opacity: 0.4
      });
      const icoMesh = new THREE.Mesh(icoGeo, icoMat);
      group.add(icoMesh);
      this.icoMesh = icoMesh;

      // 2. Inner glowing core node (Cyber Emerald reactor core)
      const coreGeo = new THREE.SphereGeometry(0.85, 16, 16);
      const coreMat = new THREE.MeshBasicMaterial({
        color: 0x10b981,
        wireframe: true,
        transparent: true,
        opacity: 0.55
      });
      const coreMesh = new THREE.Mesh(coreGeo, coreMat);
      group.add(coreMesh);
      this.coreMesh = coreMesh;

      // 3. Orbiting perimeter rings (Royal Violet & Sky Cyan)
      const ring1Geo = new THREE.TorusGeometry(3.1, 0.025, 16, 80);
      const ring1Mat = new THREE.MeshBasicMaterial({ color: 0xa855f7, transparent: true, opacity: 0.5 });
      const ring1 = new THREE.Mesh(ring1Geo, ring1Mat);
      ring1.rotation.x = Math.PI / 2.3;
      group.add(ring1);
      this.ring1 = ring1;

      const ring2Geo = new THREE.TorusGeometry(3.4, 0.02, 16, 80);
      const ring2Mat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.4 });
      const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
      ring2.rotation.y = Math.PI / 3;
      ring2.rotation.x = Math.PI / 5;
      group.add(ring2);
      this.ring2 = ring2;

      // 4. Expanding shockwave ring (Electric Cyan pulse wave)
      const pRingGeo = new THREE.RingGeometry(0.8, 0.95, 36);
      const pRingMat = new THREE.MeshBasicMaterial({ color: 0x00f2fe, transparent: true, opacity: 0, side: THREE.DoubleSide });
      const pRing = new THREE.Mesh(pRingGeo, pRingMat);
      group.add(pRing);
      this.pulseRing = pRing;

      // 5. Orbital particle constellation (multi-spectral connected nodes: Cyan, Violet, Amber)
      const nodeCount = 140;
      const positions = new Float32Array(nodeCount * 3);
      const colors = new Float32Array(nodeCount * 3);
      const cCyan = new THREE.Color(0x00f2fe);
      const cViolet = new THREE.Color(0xa855f7);
      const cAmber = new THREE.Color(0xfbbf24);

      for (let i = 0; i < nodeCount; i++) {
        const radius = 1.4 + Math.random() * 2.0;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos((Math.random() * 2) - 1);
        positions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
        positions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
        positions[i * 3 + 2] = radius * Math.cos(phi);

        const rand = Math.random();
        const col = rand < 0.45 ? cCyan : (rand < 0.8 ? cViolet : cAmber);
        colors[i * 3] = col.r;
        colors[i * 3 + 1] = col.g;
        colors[i * 3 + 2] = col.b;
      }

      const pGeo = new THREE.BufferGeometry();
      pGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
      pGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));
      const pMat = new THREE.PointsMaterial({
        size: 0.075,
        vertexColors: true,
        transparent: true,
        opacity: 0.85,
        blending: THREE.AdditiveBlending
      });
      const points = new THREE.Points(pGeo, pMat);
      group.add(points);
      this.points = points;

      // Interactive mouse orbit
      const onPointerDown = (e: MouseEvent | TouchEvent) => {
        this.isPointerDown = true;
        const clientX = 'touches' in e ? e.touches[0].clientX : e.clientX;
        const clientY = 'touches' in e ? e.touches[0].clientY : e.clientY;
        this.prevPointerX = clientX;
        this.prevPointerY = clientY;
      };
      const onPointerMove = (e: MouseEvent | TouchEvent) => {
        if (!this.isPointerDown || !this.threeMeshGroup) return;
        const clientX = 'touches' in e ? e.touches[0].clientX : e.clientX;
        const clientY = 'touches' in e ? e.touches[0].clientY : e.clientY;
        const dx = clientX - this.prevPointerX;
        const dy = clientY - this.prevPointerY;
        this.threeMeshGroup.rotation.y += dx * 0.008;
        this.threeMeshGroup.rotation.x += dy * 0.008;
        this.prevPointerX = clientX;
        this.prevPointerY = clientY;
      };
      const onPointerUp = () => { this.isPointerDown = false; };

      host.addEventListener('mousedown', onPointerDown as any);
      window.addEventListener('mousemove', onPointerMove as any);
      window.addEventListener('mouseup', onPointerUp);
      host.addEventListener('touchstart', onPointerDown as any, { passive: true });
      window.addEventListener('touchmove', onPointerMove as any, { passive: true });
      window.addEventListener('touchend', onPointerUp);
      host.addEventListener('click', () => this.triggerPulseWave());

      // Resize observer
      const resize = () => { this.resizeThree(); };
      this.threeResizeObs = new ResizeObserver(resize);
      this.threeResizeObs.observe(host);

      // Animation loop
      let clock = 0;
      const animate = () => {
        this.threeAnimId = requestAnimationFrame(animate);
        const spd = this.threeSpeed();
        clock += 0.015 * spd;
        if (!this.isPointerDown && this.threeMeshGroup) {
          this.threeMeshGroup.rotation.y += 0.005 * spd;
          this.threeMeshGroup.rotation.x += 0.0015 * spd;
        }
        ring1.rotation.z += 0.004 * spd;
        ring2.rotation.z -= 0.006 * spd;
        const scale = 1 + Math.sin(clock * 2) * 0.04;
        coreMesh.scale.set(scale, scale, scale);

        if (this.pulseOpacity > 0 && this.pulseRing) {
          this.pulseScale += 0.08 * spd;
          this.pulseOpacity -= 0.015 * spd;
          this.pulseRing.scale.set(this.pulseScale, this.pulseScale, this.pulseScale);
          (this.pulseRing.material as THREE.MeshBasicMaterial).opacity = Math.max(0, this.pulseOpacity);
        }

        renderer.render(scene, camera);
      };
      animate();
    } catch (e) {
      console.warn('Three.js Cyber Topology initialization warning:', e);
    }
  }

  private resizeThree() {
    const host = this.threeCanvasRef?.nativeElement;
    if (!host || !this.threeCamera || !this.threeRenderer) return;
    const rect = host.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    this.threeCamera.aspect = rect.width / rect.height;
    this.threeCamera.updateProjectionMatrix();
    this.threeRenderer.setSize(rect.width, rect.height, false);
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
            if (errors === 0) {
              const username = this.users().find(u => u.id === userId)?.username || userId;
              this.pushLiveEvent('sensor', 'Sensor Access Granted', `${username} · ${total} sensor(s)`, 'SYNCED', 'badge-sync');
            }
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
        const username = this.users().find(u => u.id === userId)?.username || userId;
        this.pushLiveEvent('sensor', 'Sensor Access Revoked', username, 'REMOVED', 'badge-stable');
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
          const username = this.userForm.username.trim();
          const role = this.userForm.role;
          this.closeForm();
          this.showMessage('User created for this tenant', 'success');
          this.pushLiveEvent('auth', 'Account Created', `${username} · ${this.getRoleLabel(role)}`, 'CREATED', 'badge-valid');
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
    const username = this.users().find(u => u.id === userId)?.username || userId;
    this.users.update(list => list.map(u => u.id === userId ? { ...u, permissions, active } : u));
    this.updateCharts();
    this.closeForm();
    this.showMessage(active ? 'User updated successfully' : 'User disabled successfully', 'success');
    this.pushLiveEvent(
      'policy',
      active ? 'Account Access Updated' : 'Account Disabled',
      username,
      active ? 'UPDATED' : 'DISABLED',
      active ? 'badge-priv' : 'badge-stable'
    );
  }

  deleteUser(user: TenantUser) {
    if (!confirm(`Delete user "${user.username}" from this tenant?`)) return;
    this.api.deleteUser(user.id).subscribe({
      next: () => {
        this.users.update(list => list.filter(u => u.id !== user.id));
        this.showMessage('User deleted', 'success');
        this.pushLiveEvent('auth', 'Account Deleted', user.username, 'REMOVED', 'badge-stable');
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
      datasets: [{
        data: [analyst, senior, viewer],
        backgroundColor: ['#00f2fe', '#a855f7', '#6366f1'],
        hoverBackgroundColor: ['#38bdf8', '#c084fc', '#818cf8'],
        borderWidth: 4,
        borderColor: '#171b37',
        hoverOffset: 6
      }]
    });

    const active   = this.activeUsers();
    const disabled = list.length - active;
    this.statusChartData.set({
      labels: ['Active', 'Disabled'],
      datasets: [{
        data: [active, disabled],
        backgroundColor: ['#10b981', '#1e2640'],
        hoverBackgroundColor: ['#34d399', '#2e3859'],
        borderWidth: 4,
        borderColor: '#171b37',
        hoverOffset: 6
      }]
    });

    // Real account-growth timeline — buckets actual created_at timestamps.
    // No fabricated "auth velocity"/"policy clearance" event history exists,
    // so this shows what we can genuinely measure: when accounts were made.
    const tf = this.authTimeframe();
    const bucketPlan: Record<string, { count: number; stepMs: number; unit: 'h' | 'd' }> = {
      '6h':  { count: 6,  stepMs: 3_600_000,      unit: 'h' },
      '12h': { count: 6,  stepMs: 2 * 3_600_000,  unit: 'h' },
      '24h': { count: 12, stepMs: 2 * 3_600_000,  unit: 'h' },
      '7d':  { count: 7,  stepMs: 24 * 3_600_000, unit: 'd' },
    };
    const plan = bucketPlan[tf] || bucketPlan['24h'];
    const counts = this.bucketByCreatedAt(list, plan.count, plan.stepMs);
    const unitMs = plan.unit === 'd' ? 86_400_000 : 3_600_000;
    const labels = Array.from({ length: plan.count }, (_, i) => {
      const stepsAgo = (plan.count - 1 - i) * (plan.stepMs / unitMs);
      return stepsAgo === 0 ? (plan.unit === 'd' ? 'Today' : 'Now') : `-${stepsAgo}${plan.unit}`;
    });

    this.authTimelineChartData.set({
      labels,
      datasets: [
        {
          label: 'Accounts Created',
          data: counts,
          borderColor: '#00f2fe',
          backgroundColor: 'transparent',
          fill: false,
          pointBackgroundColor: '#00f2fe',
          pointBorderColor: '#171b37',
          pointBorderWidth: 2
        }
      ]
    });

    // Real per-category access counts — from each user's actual permissions[],
    // grouped by the same licensed categories used in the permission editor.
    const categories = this.permissionCategories();
    const hasAnyOf = (u: TenantUser, keys: Set<string>) => {
      const perms = Array.isArray(u.permissions) ? u.permissions : [];
      return perms.some(p => keys.has(p));
    };
    this.clearanceBarChartData.set({
      labels: categories.map(c => c.title),
      datasets: [
        {
          label: 'Analyst Tier',
          data: categories.map(c => {
            const keys = new Set(c.options.map(o => o.key));
            return list.filter(u => u.role === 'analyst' && hasAnyOf(u, keys)).length;
          }),
          backgroundColor: '#06b6d4',
          borderRadius: 6
        },
        {
          label: 'Senior Analyst Tier',
          data: categories.map(c => {
            const keys = new Set(c.options.map(o => o.key));
            return list.filter(u => u.role === 'senior_analyst' && hasAnyOf(u, keys)).length;
          }),
          backgroundColor: '#8b5cf6',
          borderRadius: 6
        }
      ]
    });
  }

  /** Counts real user.created_at timestamps into `numBuckets` trailing windows of `stepMs`, most-recent bucket last. */
  private bucketByCreatedAt(list: TenantUser[], numBuckets: number, stepMs: number): number[] {
    const now = Date.now();
    const start = now - numBuckets * stepMs;
    const counts = new Array(numBuckets).fill(0);
    for (const u of list) {
      if (!u.created_at) continue;
      const t = new Date(u.created_at).getTime();
      if (Number.isNaN(t) || t < start || t > now) continue;
      const idx = Math.min(numBuckets - 1, Math.max(0, Math.floor((t - start) / stepMs)));
      counts[idx]++;
    }
    return counts;
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
