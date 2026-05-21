import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { Subscription } from 'rxjs';
import { LucideAngularModule, Cpu, Server, Database, CheckCircle, Activity } from 'lucide-angular';

@Component({
  selector: 'app-health',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './health.html',
  styleUrl: './health.css'
})
export class Health implements OnInit, OnDestroy {

  totalEvents: number = 0;
  totalHits: number = 0;
  eventsPerHour: number = 0;
  sessions: number = 0;
  sigmaRules: number = 0;

  services: any[] = [
    { name: 'Zeek IDS',        status: 'unknown', type: 'zeek',       label: 'Host Process'      },
    { name: 'Suricata EVE',    status: 'unknown', type: 'suricata',   label: 'Host Process'      },
    { name: 'Vector Pipeline', status: 'unknown', type: 'vector',     label: 'Docker Container'  },
    { name: 'Kafka Broker',    status: 'unknown', type: 'kafka',      label: 'Docker Container'  },
    { name: 'NDR Engine',      status: 'unknown', type: 'engine',     label: 'Docker Container'  },
    { name: 'ClickHouse DB',   status: 'unknown', type: 'clickhouse', label: 'Direct Install'    },
  ];

  CpuIcon = Cpu;
  ServerIcon = Server;
  DatabaseIcon = Database;
  CheckIcon = CheckCircle;
  ActivityIcon = Activity;

  private subs: Subscription[] = [];
  private refreshInterval: any;

  constructor(
    private api: Api,
    private ws: Websocket,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadHealth();
    this.refreshInterval = setInterval(() => this.loadHealth(), 10000);

    // Real-time updates via WebSocket
    this.subs.push(
      this.ws.lastAgentStatus$.subscribe(data => {
        if (!data) return;
        this.updateStatus('zeek',     data.zeek     === 'running' ? 'running' : 'stopped');
        this.updateStatus('suricata', data.suricata === 'running' ? 'running' : 'stopped');
        this.updateStatus('vector',   data.vector   === 'running' ? 'running' : 'stopped');
        this.updateStatus('kafka',    data.kafka     === 'running' ? 'running' : 'stopped');
        this.cdr.detectChanges();
      })
    );
  }

  loadHealth() {
    // Single API call — /api/health returns everything
    this.api.getDashboardStats().subscribe({
      next: (data: any) => {
        this.totalEvents   = data.events_total || 0;
        this.totalHits     = data.hits_total   || 0;
        this.eventsPerHour = data.events_1h    || 0;
        this.sessions      = data.sessions     || 0;
        this.sigmaRules    = data.sigma_rules  || 0;

        // Update all service statuses from services object
        const svc = data.services || {};
        this.updateStatus('zeek',       svc.zeek       || 'unknown');
        this.updateStatus('suricata',   svc.suricata   || 'unknown');
        this.updateStatus('vector',     svc.vector     || 'unknown');
        this.updateStatus('kafka',      svc.kafka      || 'unknown');
        this.updateStatus('engine',     svc.engine     || 'running');
        this.updateStatus('clickhouse', svc.clickhouse || 'unknown');
        this.cdr.detectChanges();
      },
      error: () => {
        ['zeek', 'suricata', 'vector', 'kafka', 'engine', 'clickhouse']
          .forEach(s => this.updateStatus(s, 'stopped'));
        this.cdr.detectChanges();
      }
    });
  }

  updateStatus(type: string, status: string) {
    const svc = this.services.find(s => s.type === type);
    if (svc) svc.status = status;
  }

  getStatusDotClass(status: string): string {
    switch (status) {
      case 'running': return 'bg-primary shadow-[0_0_8px_rgba(105,246,184,0.4)]';
      case 'stopped': return 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.4)]';
      default:        return 'bg-yellow-500 animate-pulse';
    }
  }

  getStatusBadgeClass(status: string): string {
    switch (status) {
      case 'running': return 'text-primary border-primary/20 bg-primary/5';
      case 'stopped': return 'text-red-400 border-red-500/20 bg-red-500/5';
      default:        return 'text-yellow-400 border-yellow-500/20 bg-yellow-500/5';
    }
  }

  getStatusLabel(status: string): string {
    switch (status) {
      case 'running': return 'Healthy';
      case 'stopped': return 'Down';
      default:        return 'Unknown';
    }
  }

  get runningCount(): number {
    return this.services.filter(s => s.status === 'running').length;
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
    if (this.refreshInterval) clearInterval(this.refreshInterval);
  }
}
