import { Component, OnInit, OnDestroy, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Download, Plus, RefreshCw, X,
} from 'lucide-angular';
import { Api } from '../../../services/api/api';

@Component({
  selector: 'app-engines',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './engines.html',
  styleUrl: './engines.css',
})
export class Engines implements OnInit, OnDestroy {
  DownloadIcon = Download;
  PlusIcon     = Plus;
  RefreshIcon  = RefreshCw;
  XIcon        = X;

  engines: any[]    = [];
  loadingEngines    = false;
  scaling           = false;
  pendingStopEngine = '';
  lastEngineRefresh: Date | null = null;

  kafkaData: any    = null;
  kafkaLoading      = false;
  private kafkaInterval: any = null;

  syncingRules  = false;
  syncMessage   = '';
  syncError     = false;

  msg     = '';
  msgType = '';

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.loadEngines();
    this.loadKafkaStatus();
    this.kafkaInterval = setInterval(() => this.loadKafkaStatus(), 10000);
  }

  ngOnDestroy() {
    if (this.kafkaInterval) clearInterval(this.kafkaInterval);
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
      error: () => { this.loadingEngines = false; this.showMsg('Failed to load engines', 'error'); this.cdr.detectChanges(); },
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

  requestStopEngine(engine: string) { this.pendingStopEngine = engine; }
  cancelStopEngine()                { this.pendingStopEngine = ''; }

  confirmStopEngine() {
    if (!this.pendingStopEngine) return;
    const engine = this.pendingStopEngine;
    this.api.scaleEngines('down', engine).subscribe({
      next: (data: any) => {
        this.pendingStopEngine = '';
        this.showMsg(data.message, 'success');
        setTimeout(() => this.loadEngines(), 2000);
      },
      error: (err: any) => { this.showMsg(err.error?.message || 'Failed to scale down', 'error'); },
    });
  }

  loadKafkaStatus() {
    this.kafkaLoading = !this.kafkaData;
    this.api.getKafkaStatus().subscribe({
      next: (data: any) => { this.kafkaData = data; this.kafkaLoading = false; this.cdr.detectChanges(); },
      error: () => { this.kafkaLoading = false; this.cdr.detectChanges(); },
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

  syncCommunityRules() {
    this.syncingRules = true;
    this.syncMessage  = '';
    this.syncError    = false;
    this.api.syncCommunityRules().subscribe({
      next: (res: any) => {
        this.syncingRules = false;
        this.syncMessage  = res.message || `${res.new_rules ?? 0} community rules synced from SigmaHQ`;
        this.syncError    = false;
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.syncingRules = false;
        this.syncMessage  = err?.error?.error || 'Sync failed';
        this.syncError    = true;
        this.cdr.detectChanges();
      },
    });
  }

  showMsg(msg: string, type: string) {
    this.msg = msg; this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
