import { Component, OnDestroy, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { ArkimeService } from '../../services/arkime/arkime';
import { EvidenceService } from '../../services/evidence/evidence';
import { Subscription } from 'rxjs';
import { ActivatedRoute, Router } from '@angular/router';
import { LucideAngularModule, AlertTriangle, Download, ExternalLink, MoreHorizontal, Package, RefreshCw, ShieldAlert, X } from 'lucide-angular';
import { AuthService } from '../../services/auth/auth';
import { SensorScopeBanner } from '../../components/sensor-scope-banner/sensor-scope-banner';

@Component({
  selector: 'app-alerts',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule, SensorScopeBanner],
  templateUrl: './alerts.html',
  styleUrl: './alerts.css',
})
export class Alerts implements OnInit, OnDestroy {
  alerts: any[] = [];
  private allAlerts: any[] = [];
  loading: boolean = true;
  activeSeverity: string = '';
  priorityOnly: boolean = false;

  // PCAP modal state
  showPcapModal = false;
  pcapLoading = false;
  pcapSessions: any[] = [];
  pcapError = '';

  ShieldAlertIcon = ShieldAlert;
  AlertTriangleIcon = AlertTriangle;
  DownloadIcon = Download;
  ExternalLinkIcon = ExternalLink;
  MoreIcon = MoreHorizontal;
  PackageIcon = Package;
  RefreshIcon = RefreshCw;
  XIcon = X;

  private subs: Subscription[] = [];

  /** Sensor IDs this user is scoped to (from JWT). */
  sensorIds: string[] = [];

  constructor(
    private api: Api,
    private ws: Websocket,
    private route: ActivatedRoute,
    private router: Router,
    private cdr: ChangeDetectorRef,
    private arkime: ArkimeService,
    private evidenceService: EvidenceService,
    private auth: AuthService,
  ) {}

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();

    this.subs.push(
      this.route.queryParamMap.subscribe(params => {
        this.activeSeverity = params.get('severity')?.toUpperCase() || '';
        this.priorityOnly = params.get('priority') === 'true';
        this.applyFilters();
        this.cdr.detectChanges();
      })
    );

    this.loadAlerts();

    // Real-time - use continuous hits from background WebSocket service
    this.subs.push(
      this.ws.continuousHits$.subscribe(hits => {
        if (!hits || hits.length === 0) return;
        
        const formattedHits = hits.map(hit => {
          const srcIp = hit.src_ip || hit.src || hit['agent-z']?.src || hit['agent-s']?.src || '';
          const dstIp = hit.dst_ip || hit.dst || hit['agent-z']?.dst || hit['agent-s']?.dst || '';
          return {
            severity: hit.severity?.toUpperCase() || 'LOW',
            source: `${srcIp || '-'} -> ${dstIp || '-'}`,
            description: hit.sigma_hits?.join(', ') || hit.tags?.join(', ') || 'Correlation hit',
            time: hit.ts
              ? new Date(hit.ts * 1000).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
              : new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            score: hit.score,
            community_id: hit.cid || hit.community_id || '',
            src_ip: srcIp,
            dst_ip: dstIp,
            src_country: this.formatOrigin(srcIp, hit.src_country),
            dst_country: hit.dst_country,
            threat_intel: hit.threat_intel || false,
            tags: hit.tags || [],
            src_asset: hit.src_asset || null,
            dst_asset: hit.dst_asset || null,
          };
        });
        
        const existingCids = new Set(formattedHits.map(h => h.community_id));
        const oldAlerts = this.allAlerts.filter(a => !existingCids.has(a.community_id));
        
        this.allAlerts = [...formattedHits, ...oldAlerts];
        if (this.allAlerts.length > 100) this.allAlerts = this.allAlerts.slice(0, 100);
        
        this.loading = false;
        this.applyFilters();
        this.cdr.detectChanges();
      })
    );
  }

  loadAlerts() {
    if (this.allAlerts.length === 0) {
      this.loading = true;
    }
    this.api.getAlerts().subscribe({
      next: (data: any[]) => {
        const apiAlerts = data.map(hit => ({
          severity: hit.severity?.toUpperCase() || 'LOW',
          source: `${hit.src_ip || '-'} -> ${hit.dst_ip || '-'}`,
          description: hit.sigma_hits?.join(', ') || hit.tags?.join(', ') || 'Correlation hit',
          time: this.formatAlertTime(
            hit.timestamp != null && hit.timestamp !== 0 ? hit.timestamp
              : hit.time != null ? hit.time
              : null
          ),
          score: hit.score,
          threat_intel: hit.threat_intel,
          community_id: hit.community_id || hit.cid || '',
          src_ip: hit.src_ip || '',
          dst_ip: hit.dst_ip || '',
          src_country: this.formatOrigin(hit.src_ip, hit.src_country),
          dst_country: hit.dst_country,
          src_asset: hit.src_asset || null,
          dst_asset: hit.dst_asset || null,
          tags: hit.tags || [],
        }));

        const existingCids = new Set(this.allAlerts.map(a => a.community_id));
        const newApiAlerts = apiAlerts.filter(a => !existingCids.has(a.community_id));
        
        this.allAlerts = [...this.allAlerts, ...newApiAlerts];
        if (this.allAlerts.length > 100) {
            this.allAlerts = this.allAlerts.slice(0, 100);
        }

        this.applyFilters();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  private applyFilters() {
    this.alerts = this.allAlerts.filter(alert => {
      const severity = alert.severity?.toUpperCase();
      if (this.activeSeverity && severity !== this.activeSeverity) return false;
      if (this.priorityOnly && !['CRITICAL', 'HIGH'].includes(severity)) return false;
      return true;
    });
  }

  // ── Summary counts always reflect ALL loaded alerts, not just filtered view ──
  get totalAlerts() {
    return this.allAlerts.length;
  }

  get priorityAlerts() {
    return this.allAlerts.filter(alert => ['CRITICAL', 'HIGH'].includes(alert.severity?.toUpperCase())).length;
  }

  get mediumAlerts() {
    return this.allAlerts.filter(alert => alert.severity?.toUpperCase() === 'MEDIUM').length;
  }

  get intelAlerts() {
    return this.allAlerts.filter(alert => alert.threat_intel).length;
  }

  getScoreClass(score: number) {
    if (score > 70) return 'score-high';
    if (score > 40) return 'score-medium';
    return 'score-low';
  }

  getSeverityClass(severity: string) {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      default:
        return 'bg-primary/10 text-primary border-primary/20';
    }
  }

  private formatAlertTime(value: unknown): string {
    const date = this.parseAlertDate(value);
    return date ? date.toLocaleString() : '--';
  }

  private parseAlertDate(value: unknown): Date | null {
    if (value === null || value === undefined || value === '') {
      return null;
    }

    if (typeof value === 'number') {
      const millis = value > 9999999999 ? value : value * 1000;
      const date = new Date(millis);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    const raw = String(value).trim();
    if (/^\d+$/.test(raw)) {
      return this.parseAlertDate(Number(raw));
    }

    const normalized = raw.includes('T') ? raw : raw.replace(' ', 'T');
    const withTimezone = /Z$|[+-]\d{2}:?\d{2}$/.test(normalized)
      ? normalized
      : `${normalized}Z`;
    const date = new Date(withTimezone);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  private formatOrigin(srcIp: string | undefined, country: string | undefined): string {
    if (country) {
      return country;
    }

    if (this.isPrivateIp(srcIp || '')) {
      return 'Internal network';
    }

    return 'Origin unavailable';
  }

  private isPrivateIp(ip: string): boolean {
    if (
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
    ) {
      return true;
    }

    const lower = ip.toLowerCase();
    return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:');
  }

  viewPcap(cid: string) {
    if (!cid) return;
    this.pcapSessions = [];
    this.pcapError = '';
    this.pcapLoading = true;
    this.showPcapModal = true;
    this.arkime.getSessions({ cid, limit: 20 }).subscribe({
      next: (data: any) => {
        this.pcapSessions = data.sessions || [];
        this.pcapLoading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.pcapError = 'Failed to load PCAP sessions';
        this.pcapLoading = false;
        this.cdr.detectChanges();
      },
    });
  }

  openArkime(cid: string) {
    if (!cid) return;
    this.arkime.getSessionLink(cid).subscribe({
      next: (data: any) => {
        if (data.link) window.open(data.link, '_blank');
      },
    });
  }

  downloadPcap(sessionId: string) {
    this.arkime.downloadPcap(sessionId);
  }

  formatBytes(bytes: number): string {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  }

  downloadEvidence(communityId: string) {
    this.evidenceService.downloadBundle(communityId);
  }

  viewTimeline(communityId: string) {
    this.router.navigate(['/evidence'],
      { queryParams: { cid: communityId } });
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}
