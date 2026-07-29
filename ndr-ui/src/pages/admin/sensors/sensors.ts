import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Copy, KeyRound, RefreshCw, X,
} from 'lucide-angular';
import { Api, SensorKey } from '../../../services/api/api';

@Component({
  selector: 'app-sensors',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './sensors.html',
  styleUrl: './sensors.css',
})
export class Sensors implements OnInit {
  CopyIcon    = Copy;
  KeyIcon     = KeyRound;
  RefreshIcon = RefreshCw;
  XIcon       = X;

  tenants: any[]          = [];
  sensorKeys: SensorKey[] = [];
  loadingSensorKeys       = false;
  creatingSensorKey       = false;
  newSensorKey            = { tenant_id: '', name: '' };
  createdSensorKey: SensorKey | null = null;
  showSensorKeyModal      = false;
  installCommand          = '';

  msg     = '';
  msgType = '';

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.loadSensorKeys();
    this.api.getTenants().subscribe({
      next: (data: any) => { this.tenants = data.tenants || []; this.cdr.detectChanges(); },
      error: () => {},
    });
  }

  loadSensorKeys() {
    this.loadingSensorKeys = true;
    this.api.getSensorKeys().subscribe({
      next: (keys: SensorKey[]) => { this.sensorKeys = keys; this.loadingSensorKeys = false; this.cdr.detectChanges(); },
      error: () => { this.loadingSensorKeys = false; this.showMsg('Failed to load sensor keys', 'error'); this.cdr.detectChanges(); },
    });
  }

  createSensorKey() {
    const tenantId = this.newSensorKey.tenant_id;
    const name     = this.newSensorKey.name.trim();
    if (!tenantId || !name) { this.showMsg('Tenant and sensor name are required', 'error'); return; }

    this.creatingSensorKey = true;
    this.api.createSensorKey(tenantId, name).subscribe({
      next: (data: any) => {
        this.creatingSensorKey = false;
        if (data.status === 'ok' && data.key) {
          this.createdSensorKey = {
            id: data.id, key: data.key, key_prefix: data.key.slice(0, 16),
            tenant_id: tenantId, name, active: true, created_at: new Date().toISOString(), last_seen: '',
          };
          this.installCommand = `sudo bash install-sensor.sh --cloud-url https://your-ndr.com --tenant-id ${tenantId} --api-key ${data.key}`;
          this.showSensorKeyModal = true;
          this.newSensorKey = { tenant_id: '', name: '' };
          this.loadSensorKeys();
        } else {
          this.showMsg(data.message || 'Failed to create sensor key', 'error');
        }
        this.cdr.detectChanges();
      },
      error: () => { this.creatingSensorKey = false; this.showMsg('Failed to create sensor key', 'error'); this.cdr.detectChanges(); },
    });
  }

  revokeSensorKey(key: SensorKey) {
    if (!key.active) return;
    this.api.revokeSensorKey(key.id).subscribe({
      next: (data: any) => {
        if (!data.status || data.status === 'ok') { key.active = false; this.showMsg('Sensor key revoked', 'success'); this.loadSensorKeys(); }
        else { this.showMsg(data.message || 'Failed to revoke sensor key', 'error'); }
        this.cdr.detectChanges();
      },
      error: () => { this.showMsg('Failed to revoke sensor key', 'error'); this.cdr.detectChanges(); },
    });
  }

  reactivateSensorKey(key: SensorKey) {
    if (key.active) return;
    this.api.reactivateSensorKey(key.id).subscribe({
      next: (data: any) => {
        if (!data.status || data.status === 'ok') { key.active = true; this.showMsg('Sensor key reactivated', 'success'); this.loadSensorKeys(); }
        else { this.showMsg(data.message || 'Failed to reactivate sensor key', 'error'); }
        this.cdr.detectChanges();
      },
      error: () => { this.showMsg('Failed to reactivate sensor key', 'error'); this.cdr.detectChanges(); },
    });
  }

  closeSensorKeyModal()    { this.showSensorKeyModal = false; }
  copyCreatedSensorKey()   { if (this.createdSensorKey?.key) this.copyText(this.createdSensorKey.key, 'Sensor key copied'); }
  copyInstallCommand()     { if (this.installCommand) this.copyText(this.installCommand, 'Install command copied'); }

  tenantName(id: string)   { return this.tenants.find(t => t.id === id)?.name || id; }

  private copyText(value: string, successMessage: string) {
    navigator.clipboard.writeText(value).then(
      () => { this.showMsg(successMessage, 'success'); this.cdr.detectChanges(); },
      () => { this.showMsg('Failed to copy to clipboard', 'error'); this.cdr.detectChanges(); }
    );
  }

  showMsg(msg: string, type: string) {
    this.msg = msg; this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
