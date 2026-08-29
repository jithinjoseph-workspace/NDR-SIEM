import {
  Component, OnInit, OnDestroy, ChangeDetectionStrategy,
  signal, ViewEncapsulation,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import {
  LucideAngularModule,
  Users, Globe, Activity, User, Settings, HelpCircle,
  Building2, ArrowUpCircle, RefreshCw, Loader, ShieldCheck, X, Radio,
} from 'lucide-angular';
import { Api } from '../../services/api/api';
import { AuthService } from '../../services/auth/auth';
import { Router } from '@angular/router';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-tenant-admin-layout',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './tenant-admin-layout.html',
  styleUrls: [
    '../sidebar/sidebar.css',
    '../../pages/tenant-admin/tenant-admin.css',
  ],
})
export class TenantAdminLayout implements OnInit, OnDestroy {
  UsersIcon         = Users;
  GlobeIcon         = Globe;
  ActivityIcon      = Activity;
  UserIcon          = User;
  SettingsIcon      = Settings;
  HelpCircleIcon    = HelpCircle;
  BuildingIcon      = Building2;
  RadioIcon         = Radio;

  hasSiem = false;
  ArrowUpCircleIcon = ArrowUpCircle;
  RefreshCwIcon     = RefreshCw;
  LoaderIcon        = Loader;
  ShieldIcon        = ShieldCheck;
  XIcon             = X;

  readonly tenantId   = signal('');
  readonly tenantName = signal('Organization');

  readonly tenantSystemStatus = signal<'OPERATIONAL' | 'DEGRADED' | 'CHECKING...'>('CHECKING...');

  readonly updateAvailable  = signal(false);
  readonly currentVersion   = signal('');
  readonly latestVersion    = signal('');
  readonly showUpdateDialog = signal(false);
  readonly updateApplying   = signal(false);
  readonly updateMessage    = signal('');
  readonly message          = signal('');
  readonly messageType      = signal<'success' | 'error'>('success');

  private statusInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    private api: Api,
    private auth: AuthService,
    private router: Router,
  ) {}

  ngOnInit() {
    const user = this.auth.getUser() || {};
    this.tenantId.set(user.tenant_id || 'default');
    this.tenantName.set(this.formatTenantName(user.tenant_id || 'default'));

    if (!['admin', 'super_admin', 'tenant_admin'].includes(user.role)) {
      this.router.navigate(['/dashboard']);
      return;
    }

    this.hasSiem = this.auth.hasFeature('siem');
    this.refreshTenantSystemStatus();
    this.statusInterval = setInterval(() => this.refreshTenantSystemStatus(), 10000);
    this.checkForUpdates();
  }

  ngOnDestroy() {
    if (this.statusInterval) clearInterval(this.statusInterval);
  }

  checkForUpdates() {
    this.api.getVersionStatus().subscribe({
      next: (data: any) => {
        this.currentVersion.set(data.current_version || '');
        this.latestVersion.set(data.latest_version  || '');
        this.updateAvailable.set(!!data.update_available);
      },
      error: () => {}
    });
  }

  openUpdateDialog()  { this.showUpdateDialog.set(true); this.updateMessage.set(''); }
  closeUpdateDialog() { this.showUpdateDialog.set(false); }

  confirmApplyUpdate() {
    this.updateApplying.set(true);
    this.updateMessage.set('');

    if (this.statusInterval) { clearInterval(this.statusInterval); this.statusInterval = null; }
    const resumePolling = () => {
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
                resumePolling();
              }
            },
            error: () => { attempts++; }
          });
        }, 5000);
      },
      error: (err: any) => {
        this.updateMessage.set(err?.error?.message || 'Update request failed');
        this.updateApplying.set(false);
        resumePolling();
      }
    });
  }

  private refreshTenantSystemStatus() {
    this.api.getSensorKeys().subscribe({
      next: (sensors: any[]) => {
        const healthyPipeline = sensors.length === 0 ||
          sensors.some(s =>
            s.active !== false &&
            (this.isRunning(s['agent-z']) || this.isRunning(s['agent-s']) || this.isRunning(s.vector))
          );

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

  showMessage(message: string, type: 'success' | 'error') {
    this.message.set(message);
    this.messageType.set(type);
    setTimeout(() => this.message.set(''), 5000);
  }

  private formatTenantName(tenantId: string) {
    return tenantId.split(/[-_]/).filter(Boolean)
      .map(part => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ') || 'Organization';
  }
}
