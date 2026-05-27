import { Component, OnDestroy, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import {
  LucideAngularModule,
  Activity,
  Play,
  RefreshCcw,
  Server,
  Settings,
  ShieldCheck,
  Square,
} from 'lucide-angular';
import { Subscription, timer } from 'rxjs';
import { filter } from 'rxjs/operators';
import { Api, SensorControlCommand, SensorKey } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { AuthService } from '../../services/auth/auth';

type SetupTab = 'local' | 'external';
type ExternalServiceStatus = 'running' | 'stopped' | 'restarting' | 'unknown';

interface ExternalSensorCard extends SensorKey {
  hostname: string;
  interface: string;
  os: string;
  zeek: ExternalServiceStatus;
  suricata: ExternalServiceStatus;
  vector: ExternalServiceStatus;
  online: boolean;
}

@Component({
  selector: 'app-setup',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './setup.html',
  styleUrl: './setup.css',
})
export class Setup implements OnInit, OnDestroy {
  interfaces: string[] = [];
  selectedInterface = '';
  status: 'Ready' | 'Starting...' | 'Running' | 'Stopping...' | 'Stopped' = 'Ready';
  zeekStatus = 'stopped';
  suricataStatus = 'stopped';
  vectorStatus = 'stopped';
  activeTab: SetupTab = 'local';
  externalSensors: ExternalSensorCard[] = [];
  externalLoading = false;
  externalError = '';
  externalActionMessage = '';
  pendingExternalCommand: { tenantId: string; command: SensorControlCommand } | null = null;

  private subs: Subscription[] = [];
  private currentRole = '';
  private currentTenantId = '';

  SettingsIcon = Settings;
  PlayIcon = Play;
  StopIcon = Square;
  RefreshIcon = RefreshCcw;
  ShieldIcon = ShieldCheck;
  ActivityIcon = Activity;
  ServerIcon = Server;

  constructor(
    private api: Api,
    private ws: Websocket,
    private cdr: ChangeDetectorRef,
    private auth: AuthService,
    private router: Router
  ) {}

  ngOnInit() {
    const user = this.auth.getUser();
    if (user?.tenant_id !== 'default' && user?.role !== 'tenant_admin') {
      this.router.navigate(['/dashboard']);
      return;
    }

    this.currentRole = user?.role || '';
    this.currentTenantId = user?.tenant_id || '';
    this.activeTab =
      this.currentRole === 'tenant_admin' && this.currentTenantId !== 'default'
        ? 'external'
        : 'local';

    this.loadLocalSensorSetup();

    if (this.canViewExternalSensors) {
      this.loadExternalSensors();
      this.subs.push(
        timer(30000, 30000).subscribe(() => this.loadExternalSensors(true))
      );
    }
  }

  ngOnDestroy() {
    this.subs.forEach(subscription => subscription.unsubscribe());
  }

  get canViewExternalSensors(): boolean {
    return this.currentRole === 'super_admin' || this.currentRole === 'tenant_admin';
  }

  get localRunningCount(): number {
    return [this.zeekStatus, this.suricataStatus, this.vectorStatus]
      .filter(status => status === 'running').length;
  }

  get externalOnlineCount(): number {
    return this.externalSensors.filter(sensor => sensor.online).length;
  }

  get summaryActive(): boolean {
    return this.activeTab === 'local'
      ? this.status === 'Running'
      : this.externalOnlineCount > 0;
  }

  get summaryTitle(): string {
    if (this.activeTab === 'local') {
      return this.status;
    }

    if (!this.canViewExternalSensors) {
      return 'Unavailable';
    }

    if (this.externalLoading) {
      return 'Loading...';
    }

    if (!this.externalSensors.length) {
      return 'No Sensors';
    }

    return `${this.externalOnlineCount}/${this.externalSensors.length} Online`;
  }

  get summaryDetail(): string {
    if (this.activeTab === 'local') {
      return this.selectedInterface || 'No interface selected';
    }

    if (!this.canViewExternalSensors) {
      return 'Tenant admin or super admin required';
    }

    return this.externalSensors.length
      ? 'External sensor command queue ready'
      : 'No registered external sensors';
  }

  updateStatus(data: any) {
    this.zeekStatus = this.normalizeStatus(data.zeek);
    this.suricataStatus = this.normalizeStatus(data.suricata);
    this.vectorStatus = this.normalizeStatus(data.vector);
    this.selectedInterface = data.interface || this.selectedInterface;

    if (
      this.zeekStatus === 'running' ||
      this.suricataStatus === 'running' ||
      this.vectorStatus === 'running'
    ) {
      this.status = 'Running';
    } else if (this.status !== 'Starting...' && this.status !== 'Stopping...') {
      this.status = 'Stopped';
    }
  }

  selectTab(tab: SetupTab) {
    this.activeTab = tab;
  }

  applyInterface() {
    this.api.setInterface(this.selectedInterface).subscribe(() => {
      console.log('Interface set to', this.selectedInterface);
    });
  }

  startMonitoring() {
    this.status = 'Starting...';
    this.api.startServices().subscribe({
      next: () => {
        this.pollStatus('Running');
      },
      error: () => {
        this.status = 'Stopped';
        this.cdr.detectChanges();
      },
    });
  }

  stopMonitoring() {
    this.status = 'Stopping...';
    this.api.stopServices().subscribe({
      next: () => {
        this.pollStatus('Stopped');
      },
      error: () => {
        this.status = 'Running';
        this.cdr.detectChanges();
      },
    });
  }

  controlExternalSensor(sensor: ExternalSensorCard, command: SensorControlCommand) {
    this.pendingExternalCommand = {
      tenantId: sensor.tenant_id,
      command,
    };
    this.externalActionMessage = '';
    this.externalError = '';

    this.api.controlSensor(command, sensor.tenant_id).subscribe({
      next: response => {
        this.externalActionMessage =
          response?.message || `Command '${command}' queued for ${sensor.tenant_id}.`;
        this.pendingExternalCommand = null;
        this.loadExternalSensors(true);
        this.cdr.detectChanges();
      },
      error: error => {
        this.externalError =
          error?.error?.message || `Unable to ${command} sensor for ${sensor.tenant_id}.`;
        this.pendingExternalCommand = null;
        this.cdr.detectChanges();
      },
    });
  }

  isCommandPending(sensor: ExternalSensorCard, command?: SensorControlCommand): boolean {
    if (!this.pendingExternalCommand) {
      return false;
    }

    return this.pendingExternalCommand.tenantId === sensor.tenant_id
      && (!command || this.pendingExternalCommand.command === command);
  }

  getServiceLabel(status: ExternalServiceStatus): string {
    switch (status) {
      case 'running':
        return 'Running';
      case 'stopped':
        return 'Stopped';
      case 'restarting':
        return 'Restarting';
      default:
        return 'Unavailable';
    }
  }

  formatRelativeTime(value: string): string {
    const timestamp = this.parseDate(value);
    if (!timestamp) {
      return 'Never';
    }

    const diffMs = Date.now() - timestamp.getTime();
    const diffSeconds = Math.max(0, Math.floor(diffMs / 1000));

    if (diffSeconds < 45) return 'Just now';

    const diffMinutes = Math.floor(diffSeconds / 60);
    if (diffMinutes < 60) {
      return `${diffMinutes} minute${diffMinutes === 1 ? '' : 's'} ago`;
    }

    const diffHours = Math.floor(diffMinutes / 60);
    if (diffHours < 24) {
      return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
    }

    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
  }

  trackSensor(_index: number, sensor: ExternalSensorCard): string {
    return sensor.id;
  }

  private pollStatus(expected: string, attempts = 0) {
    setTimeout(() => {
      this.api.getAgentStatus().subscribe({
        next: (data: any) => {
          if (data) {
            const normalizedRunning =
              this.normalizeStatus(data.zeek) === 'running' ||
              this.normalizeStatus(data.suricata) === 'running' ||
              this.normalizeStatus(data.vector) === 'running';
            const matched =
              (expected === 'Running' && normalizedRunning) ||
              (expected === 'Stopped' && !normalizedRunning);

            if (matched || attempts >= 5) {
              this.status = 'Ready';
              this.updateStatus(data);
              this.cdr.detectChanges();
            } else {
              this.pollStatus(expected, attempts + 1);
            }
          }
        },
        error: () => {
          if (attempts < 5) {
            this.pollStatus(expected, attempts + 1);
          } else {
            this.status = 'Stopped';
            this.cdr.detectChanges();
          }
        },
      });
    }, 2000);
  }

  private normalizeStatus(status: unknown): string {
    const value = String(status || 'stopped').toLowerCase().trim();
    if (['running', 'healthy', 'ok', 'up', 'active', 'started'].includes(value)) return 'running';
    if (['stopped', 'down', 'error', 'failed', 'inactive', 'unknown'].includes(value)) return 'stopped';
    return /^\d+$/.test(value) ? 'running' : value;
  }

  private loadLocalSensorSetup() {
    this.api.getInterfaces().subscribe(data => {
      this.interfaces = data || [];
      this.cdr.detectChanges();
    });

    this.api.getAgentStatus().subscribe(data => {
      if (data) {
        this.updateStatus(data);
        this.cdr.detectChanges();
      }
    });

    this.subs.push(
      this.ws.lastAgentStatus$.pipe(
        filter(data => data !== null)
      ).subscribe(data => {
        this.updateStatus(data);
        this.cdr.detectChanges();
      })
    );
  }

  private loadExternalSensors(silent = false) {
    if (!this.canViewExternalSensors) {
      return;
    }

    if (!silent) {
      this.externalLoading = true;
    }
    this.externalError = '';

    this.api.getSensorKeys().subscribe({
      next: sensors => {
        this.externalSensors = sensors.map(sensor => this.mapExternalSensor(sensor));
        this.externalLoading = false;
        this.cdr.detectChanges();
      },
      error: error => {
        this.externalError = error?.error?.message || 'Unable to load external sensors.';
        this.externalLoading = false;
        this.cdr.detectChanges();
      },
    });
  }

  private mapExternalSensor(sensor: SensorKey): ExternalSensorCard {
    return {
      ...sensor,
      hostname: sensor.hostname || sensor.name || sensor.key_prefix,
      interface: sensor.interface || 'Unavailable',
      os: sensor.os || 'Unavailable',
      zeek: this.normalizeExternalStatus(sensor.zeek),
      suricata: this.normalizeExternalStatus(sensor.suricata),
      vector: this.normalizeExternalStatus(sensor.vector),
      online: sensor.active && this.isRecentlySeen(sensor.last_seen),
    };
  }

  private isRecentlySeen(value: string): boolean {
    const timestamp = this.parseDate(value);
    if (!timestamp) {
      return false;
    }

    return Date.now() - timestamp.getTime() <= 120000;
  }

  private parseDate(value: string): Date | null {
    if (!value) {
      return null;
    }

    const normalized = value.includes('T') ? value : value.replace(' ', 'T');
    const withTimezone = /Z$|[+-]\d{2}:\d{2}$/.test(normalized)
      ? normalized
      : `${normalized}Z`;
    const parsed = new Date(withTimezone);

    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }

    const fallback = new Date(value);
    return Number.isNaN(fallback.getTime()) ? null : fallback;
  }

  private normalizeExternalStatus(status: unknown): ExternalServiceStatus {
    const value = String(status || 'unknown').toLowerCase().trim();
    if (value === 'running') return 'running';
    if (value === 'stopped') return 'stopped';
    if (value === 'restarting') return 'restarting';
    return 'unknown';
  }
}
