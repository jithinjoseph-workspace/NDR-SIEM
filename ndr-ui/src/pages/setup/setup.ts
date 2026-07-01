import { Component, OnDestroy, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import {
  LucideAngularModule,
  Activity,
  Copy,
  KeyRound,
  Plus,
  Play,
  RefreshCcw,
  Server,
  Settings,
  ShieldCheck,
  Square,
  AlertTriangle,
} from 'lucide-angular';
import { Subscription, timer } from 'rxjs';
import { filter } from 'rxjs/operators';
import { Api, SensorControlCommand, SensorKey } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { AuthService } from '../../services/auth/auth';

type SetupTab = 'local' | 'external';
type ExternalServiceStatus = 'running' | 'stopped' | 'restarting' | 'unknown';

interface ExternalSensorCard extends SensorKey {
  displayName: string;
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
  arkimeStatus = 'stopped';
  activeTab: SetupTab = 'local';
  externalSensors: ExternalSensorCard[] = [];
  externalLoading = false;
  externalError = '';
  externalActionMessage = '';
  pendingExternalCommand: { sensorId: string; command: SensorControlCommand } | null = null;
  showAddSensorModal = false;
  newSensorName = '';
  creatingSensor = false;
  createdSensorKey: SensorKey | null = null;
  installCommand = '';
  keyCopied = false;
  commandCopied = false;
  cloudUrl = this.detectCloudUrl();

  showErrorModal = false;
  errorTitle = '';
  errorMessage = '';

  private subs: Subscription[] = [];
  private currentRole = '';
  private currentTenantId = '';

  SettingsIcon = Settings;
  CopyIcon = Copy;
  KeyIcon = KeyRound;
  PlusIcon = Plus;
  PlayIcon = Play;
  StopIcon = Square;
  RefreshIcon = RefreshCcw;
  ShieldIcon = ShieldCheck;
  ActivityIcon = Activity;
  ServerIcon = Server;
  AlertIcon = AlertTriangle;

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

    if (this.canViewLocalSensor) {
      this.loadLocalSensorSetup();
    }

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

  get canViewLocalSensor(): boolean {
    return this.currentTenantId === 'default';
  }

  get isDefaultTenant(): boolean {
    return this.currentTenantId === 'default';
  }

  get localRunningCount(): number {
    return [this.zeekStatus, this.suricataStatus, this.vectorStatus, this.arkimeStatus]
      .filter(status => status === 'running').length;
  }

  get externalOnlineCount(): number {
    return this.externalSensors.filter(sensor => sensor.online).length;
  }

  get externalOfflineCount(): number {
    return Math.max(this.externalSensors.length - this.externalOnlineCount, 0);
  }

  get tenantDisplayName(): string {
    return this.currentTenantId || 'Tenant';
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
    this.arkimeStatus = this.normalizeStatus(data.arkime);
    this.selectedInterface = data.interface || this.selectedInterface;

    if (
      this.zeekStatus === 'running' &&
      this.suricataStatus === 'running' &&
      this.vectorStatus === 'running' &&
      this.arkimeStatus === 'running'
    ) {
      this.status = 'Running';
    } else if (this.status !== 'Starting...' && this.status !== 'Stopping...') {
      this.status = 'Stopped';
    }
  }

  showError(title: string, message: string) {
    this.errorTitle = title;
    this.errorMessage = message;
    this.showErrorModal = true;
    this.cdr.detectChanges();
  }

  selectTab(tab: SetupTab) {
    if (tab === 'local' && !this.canViewLocalSensor) {
      return;
    }

    this.activeTab = tab;
  }

  applyInterface() {
    this.api.setInterface(this.selectedInterface).subscribe({
      next: () => { /* interface applied silently */ },
      error: (error) => {
        this.showError('Apply Interface Failed', error?.error?.message || 'Could not apply interface to local sensor. Please verify connection and try again.');
      }
    });
  }

  startMonitoring() {
    this.status = 'Starting...';
    this.api.startServices().subscribe({
      next: () => {
        this.pollStatus('Running');
      },
      error: (error) => {
        this.status = 'Stopped';
        this.cdr.detectChanges();
        this.showError('Start Monitoring Failed', error?.error?.message || 'Failed to start local sensor monitoring services (Agent-Z, Agent-S, Vector). Please check host status.');
      },
    });
  }

  stopMonitoring() {
    this.status = 'Stopping...';
    this.api.stopServices().subscribe({
      next: () => {
        this.pollStatus('Stopped');
      },
      error: (error) => {
        this.status = 'Running';
        this.cdr.detectChanges();
        this.showError('Stop Monitoring Failed', error?.error?.message || 'Failed to stop local sensor monitoring services. Please verify status on host.');
      },
    });
  }

  controlExternalSensor(sensor: ExternalSensorCard, command: SensorControlCommand) {
    const sensorName = this.getSensorDisplayName(sensor);
    this.pendingExternalCommand = {
      sensorId: sensor.key_prefix,
      command,
    };
    this.externalActionMessage = '';
    this.externalError = '';

    this.api.controlSensor(command, sensor.tenant_id, sensor.key_prefix).subscribe({
      next: () => {
        this.externalActionMessage = `${this.getCommandLabel(command)} queued for ${sensorName}.`;
        this.pendingExternalCommand = null;
        this.loadExternalSensors(true);
        this.cdr.detectChanges();
      },
      error: error => {
        this.externalError =
          error?.error?.message || `Unable to ${command} ${sensorName}.`;
        this.pendingExternalCommand = null;
        this.cdr.detectChanges();
      },
    });
  }

  openAddSensorModal() {
    this.newSensorName = '';
    this.createdSensorKey = null;
    this.installCommand = '';
    this.externalError = '';
    this.externalActionMessage = '';
    this.showAddSensorModal = true;
  }

  createExternalSensorKey() {
    const name = this.newSensorName.trim();
    if (!name) {
      this.externalError = 'Sensor name is required.';
      return;
    }

    this.creatingSensor = true;
    this.externalError = '';
    this.externalActionMessage = '';

    this.api.createSensorKey(this.currentTenantId, name).subscribe({
      next: response => {
        this.creatingSensor = false;

        if (response?.status === 'ok' && response.key) {
          this.createdSensorKey = {
            id: response.id,
            key: response.key,
            key_prefix: response.key.slice(0, 16),
            tenant_id: this.currentTenantId,
            name,
            active: true,
            created_at: new Date().toISOString(),
            last_seen: '',
          };
          this.installCommand = this.buildInstallCommand(response.key);
          this.newSensorName = '';
          this.externalActionMessage = 'Sensor key generated. Copy it before closing.';
          this.loadExternalSensors(true);
        } else {
          this.externalError = response?.message || 'Failed to generate sensor key.';
        }

        this.cdr.detectChanges();
      },
      error: error => {
        this.creatingSensor = false;
        this.externalError = error?.error?.message || 'Failed to generate sensor key.';
        this.cdr.detectChanges();
      },
    });
  }

  copyCreatedSensorKey() {
    if (this.createdSensorKey?.key) {
      this.keyCopied = false;
      navigator.clipboard.writeText(this.createdSensorKey.key).then(
        () => {
          this.keyCopied = true;
          this.externalActionMessage = 'Sensor key copied.';
          this.externalError = '';
          this.cdr.detectChanges();
          setTimeout(() => {
            this.keyCopied = false;
            this.cdr.detectChanges();
          }, 2500);
        },
        () => {
          this.externalError = 'Failed to copy to clipboard.';
          this.cdr.detectChanges();
        }
      );
    }
  }

  copyInstallCommand() {
    if (this.installCommand) {
      this.commandCopied = false;
      navigator.clipboard.writeText(this.installCommand).then(
        () => {
          this.commandCopied = true;
          this.externalActionMessage = 'Install command copied.';
          this.externalError = '';
          this.cdr.detectChanges();
          setTimeout(() => {
            this.commandCopied = false;
            this.cdr.detectChanges();
          }, 2500);
        },
        () => {
          this.externalError = 'Failed to copy to clipboard.';
          this.cdr.detectChanges();
        }
      );
    }
  }

  isSensorRunning(sensor: ExternalSensorCard): boolean {
    return sensor.zeek === 'running' || sensor.suricata === 'running' || sensor.vector === 'running';
  }

  isCommandPending(sensor: ExternalSensorCard, command?: SensorControlCommand): boolean {
    if (!this.pendingExternalCommand) {
      return false;
    }

    return this.pendingExternalCommand.sensorId === sensor.key_prefix
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
            const allRunning =
              this.normalizeStatus(data.zeek) === 'running' &&
              this.normalizeStatus(data.suricata) === 'running' &&
              this.normalizeStatus(data.vector) === 'running';
            const noneRunning =
              this.normalizeStatus(data.zeek) !== 'running' &&
              this.normalizeStatus(data.suricata) !== 'running' &&
              this.normalizeStatus(data.vector) !== 'running';

            const matched =
              (expected === 'Running' && allRunning) ||
              (expected === 'Stopped' && noneRunning);

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
    this.api.getInterfaces().subscribe({
      next: data => {
        this.interfaces = data || [];
        this.cdr.detectChanges();
      },
      error: error => {
        this.showError('Interfaces Load Failed', error?.error?.message || 'Could not load network interfaces.');
      }
    });

    this.api.getAgentStatus().subscribe({
      next: data => {
        if (data) {
          this.updateStatus(data);
          this.cdr.detectChanges();
        }
      },
      error: error => {
        this.showError('Sensor Status Load Failed', error?.error?.message || 'Could not retrieve local sensor service statuses.');
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
        this.externalSensors = this.getVisibleExternalSensors(sensors)
          .map(sensor => this.mapExternalSensor(sensor));
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

  private getVisibleExternalSensors(sensors: SensorKey[]): SensorKey[] {
    if (this.currentRole !== 'tenant_admin') {
      return sensors;
    }

    return sensors.filter(sensor => sensor.active);
  }

  private mapExternalSensor(sensor: SensorKey): ExternalSensorCard {
    const displayName = this.cleanLabel(sensor.name)
      || this.cleanLabel(sensor.hostname)
      || sensor.key_prefix;

    return {
      ...sensor,
      displayName,
      hostname: this.cleanLabel(sensor.hostname) || 'Unregistered host',
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

  private getSensorDisplayName(sensor: ExternalSensorCard): string {
    return this.cleanLabel(sensor.displayName) || this.cleanLabel(sensor.name) || sensor.key_prefix;
  }

  private cleanLabel(value: unknown): string {
    return String(value || '').trim();
  }

  private getCommandLabel(command: SensorControlCommand): string {
    switch (command) {
      case 'start':
        return 'Start command';
      case 'stop':
        return 'Stop command';
      case 'restart':
        return 'Restart command';
    }
  }

  private buildInstallCommand(key: string): string {
    return `curl -fsSL ${this.cloudUrl}/api/install-sensor.sh | sudo bash -s -- --cloud-url ${this.cloudUrl} --tenant-id ${this.currentTenantId} --api-key ${key}`;
  }

  private detectCloudUrl(): string {
    if (typeof window === 'undefined') {
      return 'https://your-ndr.com';
    }

    const url = new URL(window.location.origin);
    if (url.port === '4200') {
      url.port = '3000';
    }
    return url.origin;
  }

  private copyText(value: string, successMessage: string) {
    navigator.clipboard.writeText(value).then(
      () => {
        this.externalActionMessage = successMessage;
        this.externalError = '';
        this.cdr.detectChanges();
      },
      () => {
        this.externalError = 'Failed to copy to clipboard.';
        this.cdr.detectChanges();
      }
    );
  }
}
