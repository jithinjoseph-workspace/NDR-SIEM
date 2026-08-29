import { Component, OnInit, OnDestroy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Subscription } from 'rxjs';
import { LucideAngularModule, Search, Download, Filter, X, ChevronDown } from 'lucide-angular';

interface SiemLog {
  log_id:      string;
  source_id:   string;
  source_type: string;
  event_class: string;
  severity:    string;
  timestamp:   string;
  raw_log:     string;
  parsed:      any;
}

interface LogSearchResponse {
  logs:  SiemLog[];
  total: number;
  took_ms: number;
}

@Component({
  selector: 'app-siem-logs',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-logs.html',
  styleUrl: './siem-logs.css',
})
export class SiemLogs implements OnInit, OnDestroy {

  // ── Search state ──────────────────────────────────────────────────────────
  query        = '';
  filterSource = 'all';
  filterSev    = 'all';
  filterClass  = 'all';
  dateFrom     = '';
  dateTo       = '';
  page         = 1;
  pageSize     = 50;

  // ── Results ───────────────────────────────────────────────────────────────
  logs        = signal<SiemLog[]>([]);
  total       = signal(0);
  tookMs      = signal(0);
  loading     = signal(false);
  error       = signal<string | null>(null);
  expanded    = signal<string | null>(null);  // expanded log_id

  // ── Filter options ────────────────────────────────────────────────────────
  readonly sources    = ['all', 'wec', 'syslog', 'firewall_cef', 'generic', 'aws_cloudtrail'];
  readonly severities = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  readonly classes    = ['all', 'authentication', 'network_activity', 'process_activity',
                          'system_activity', 'account_change', 'scheduled_job_activity'];

  // ── Icons ─────────────────────────────────────────────────────────────────
  readonly SearchIcon   = Search;
  readonly DownloadIcon = Download;
  readonly FilterIcon   = Filter;
  readonly XIcon        = X;
  readonly ChevronIcon  = ChevronDown;

  private sub?: Subscription;

  constructor(private http: HttpClient) {}

  ngOnInit() { this.search(); }
  ngOnDestroy() { this.sub?.unsubscribe(); }

  search(resetPage = true) {
    if (resetPage) this.page = 1;
    this.loading.set(true);
    this.error.set(null);

    const params: any = { page: this.page, size: this.pageSize };
    if (this.query.trim())        params['q']       = this.query.trim();
    if (this.filterSource !== 'all') params['source'] = this.filterSource;
    if (this.filterSev    !== 'all') params['severity'] = this.filterSev;
    if (this.filterClass  !== 'all') params['event_class'] = this.filterClass;
    if (this.dateFrom)               params['from']   = this.dateFrom;
    if (this.dateTo)                 params['to']     = this.dateTo;

    this.sub?.unsubscribe();
    this.sub = this.http.get<LogSearchResponse>('/api/siem/logs', { params }).subscribe({
      next: res => {
        this.logs.set(res.logs ?? []);
        this.total.set(res.total ?? 0);
        this.tookMs.set(res.took_ms ?? 0);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
        this.error.set('Search failed — check siem-engine connection');
      }
    });
  }

  clearFilters() {
    this.query = ''; this.filterSource = 'all';
    this.filterSev = 'all'; this.filterClass = 'all';
    this.dateFrom = ''; this.dateTo = '';
    this.search();
  }

  toggleExpand(id: string) {
    this.expanded.set(this.expanded() === id ? null : id);
  }

  exportCsv() {
    const params: any = { format: 'csv', size: 10000 };
    if (this.query.trim()) params['q'] = this.query.trim();
    if (this.filterSource !== 'all') params['source'] = this.filterSource;
    window.open('/api/siem/logs?' + new URLSearchParams(params).toString());
  }

  get totalPages(): number { return Math.ceil(this.total() / this.pageSize); }

  prevPage() { if (this.page > 1) { this.page--; this.search(false); } }
  nextPage()  { if (this.page < this.totalPages) { this.page++; this.search(false); } }

  severityClass(s: string): string {
    return ({ CRITICAL: 'sev-critical', HIGH: 'sev-high', MEDIUM: 'sev-medium',
              LOW: 'sev-low', INFO: 'sev-info' } as any)[s] ?? 'sev-info';
  }

  sourceLabel(t: string): string {
    return ({ wec: 'WEC', syslog: 'Syslog', firewall_cef: 'CEF',
              generic: 'REST', aws_cloudtrail: 'AWS' } as any)[t] ?? t;
  }
}
