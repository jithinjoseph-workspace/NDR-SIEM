import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef, ViewEncapsulation } from '@angular/core';
import { CommonModule, DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
import { RulesBase } from '../../shared/rules/rules-base';
import {
  LucideAngularModule,
  Search, ChevronDown,
} from 'lucide-angular';

@Component({
  selector: 'app-admin-rules',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, DecimalPipe, LucideAngularModule, FormsModule],
  templateUrl: './rules.html',
  styleUrl: './rules.css',
})
export class AdminRules extends RulesBase implements OnInit {
  rules: any[]         = [];
  filteredRules: any[] = [];
  displayCount         = 20;
  isSearching          = false;
  searchQuery          = '';

  get displayedRules() { return this.filteredRules.slice(0, this.displayCount); }
  get hasMore()        { return this.displayCount < this.filteredRules.length; }
  get shownCount()     { return Math.min(this.displayCount, this.filteredRules.length); }

  templates = [
    { label: 'Agent-S Alert',   field: 'event_type',    value: 'alert',      matcher: 'equals',     title: 'Agent-S Alert Detected',  severity: 'high',     description: 'Detects any Agent-S alert' },
    { label: 'Port Scan',       field: 'conn_state',    value: 'S0',         matcher: 'equals',     title: 'Port Scan Detection',     severity: 'medium',   description: 'Detects port scans via unanswered connections' },
    { label: 'HTTP Monitor',    field: 'event_type',    value: 'http',       matcher: 'equals',     title: 'HTTP Traffic Monitor',    severity: 'low',      description: 'Monitors HTTP traffic' },
    { label: 'Critical Alert',  field: 'alert.severity',value: '1',          matcher: 'equals',     title: 'Critical Agent-S Alert',  severity: 'critical', description: 'Detects highest severity Agent-S alerts' },
    { label: 'Exec from /tmp',  field: 'Image',         value: '/tmp/',      matcher: 'startswith', title: 'Execution from /tmp',     severity: 'high',     description: 'Detects process execution from /tmp' },
    { label: 'Reverse Shell',   field: 'CommandLine',   value: 'nc -e',      matcher: 'contains',   title: 'Netcat Reverse Shell',    severity: 'critical', description: 'Detects netcat reverse shell' },
    { label: 'Cron Persistence',field: 'TargetFilename',value: '/etc/cron',  matcher: 'startswith', title: 'Cron Persistence Attempt',severity: 'high',     description: 'Detects writes to cron directories' },
    { label: 'Root Execution',  field: 'User',          value: 'root',       matcher: 'equals',     title: 'Root Process Execution',  severity: 'medium',   description: 'Detects any process executed as root' },
  ];

  SearchIcon  = Search;
  ChevronIcon = ChevronDown;

  constructor(api: Api, cdr: ChangeDetectorRef) {
    super(api, cdr);
  }

  get activeRulesCount() { return this.rules.filter(r => r.status === 'ACTIVE').length; }

  ngOnInit() { this.loadRules(); }

  private mapRule(r: any) {
    return {
      name:        r.title || 'Unknown',
      type:        'SIGMA',
      severity:    (r.severity || 'medium').toUpperCase(),
      status:      r.enabled ? 'ACTIVE' : 'INACTIVE',
      id:          r.id,
      description: r.description || '',
      tags:        r.tags || [],
      conditions:  r.conditions || 0,
      hits:        0,
    };
  }

  loadRules() {
    this.loading = true;
    this.searchQuery = '';
    this.api.getRules().subscribe({
      next: (data: any[]) => {
        // Newest first (reverse backend order which is typically oldest-first)
        this.rules = data.map(r => this.mapRule(r)).reverse();
        this.filteredRules = [...this.rules];
        this.displayCount = 20;
        this.loading = false;
        this.cdr.detectChanges();
        this.api.getRuleHitCounts().subscribe({
          next: (hitCounts: { [k: string]: number }) => {
            this.totalHits = Object.values(hitCounts).reduce((a, b) => a + b, 0);
            this.rules = this.rules.map(r => ({ ...r, hits: hitCounts[r.name] || 0 }));
            this.filteredRules = this.filteredRules.map(r => ({ ...r, hits: hitCounts[r.name] || 0 }));
            this.cdr.detectChanges();
          },
          error: reportRxjsError,
        });
      },
      error: () => { this.loading = false; this.cdr.detectChanges(); },
    });
  }

  private searchDebounce: any;

  onSearch() {
    clearTimeout(this.searchDebounce);
    const q = this.searchQuery.trim().toLowerCase();
    if (!q) {
      this.filteredRules = [...this.rules];
      this.displayCount = 20;
      this.isSearching = false;
      this.cdr.detectChanges();
      return;
    }
    const local = this.rules.filter(r =>
      r.name.toLowerCase().includes(q) ||
      (r.description || '').toLowerCase().includes(q) ||
      r.severity.toLowerCase().includes(q) ||
      (r.tags || []).some((t: string) => t.toLowerCase().includes(q))
    );
    if (local.length > 0) {
      this.filteredRules = local;
      this.displayCount = 20;
      this.isSearching = false;
      this.cdr.detectChanges();
      return;
    }
    // No local match — query backend, debounced so a fast typist doesn't
    // fire one request per keystroke (matches analyst/rules.ts's pattern).
    this.isSearching = true;
    this.filteredRules = [];
    this.cdr.detectChanges();
    this.searchDebounce = setTimeout(() => this.runBackendSearch(q), 350);
  }

  private runBackendSearch(q: string) {
    this.api.searchRules(q).subscribe({
      next: (data: any[]) => {
        this.filteredRules = data.map(r => this.mapRule(r));
        this.isSearching = false;
        this.displayCount = 20;
        this.cdr.detectChanges();
      },
      error: () => {
        this.isSearching = false;
        this.filteredRules = [];
        this.cdr.detectChanges();
      },
    });
  }

  loadMore() {
    this.displayCount = Math.min(this.displayCount + 20, this.filteredRules.length);
    this.cdr.detectChanges();
  }

  applyTemplate(t: any) {
    this.ruleForm = { ...this.ruleForm, field: t.field, value: t.value,
      matcher: t.matcher, title: t.title, severity: t.severity, description: t.description };
  }

  getSeverityClass(sev: string) {
    const map: Record<string, string> = {
      CRITICAL: 'sev-critical', HIGH: 'sev-high', MEDIUM: 'sev-medium', LOW: 'sev-low',
    };
    return map[sev?.toUpperCase()] || 'sev-low';
  }

  getTagClass(tag: string): string {
    const t = (tag || '').toLowerCase();
    if (t.includes('exfiltration') || t.includes('initial'))      return 'tag--amber';
    if (t.includes('command') || t.includes('c2') || t.includes('impact')) return 'tag--red';
    if (t.includes('privilege') || t.includes('escalation'))      return 'tag--violet';
    if (t.includes('lateral') || t.includes('movement'))          return 'tag--blue';
    if (t.includes('persist'))                                     return 'tag--orange';
    if (t.includes('discover'))                                    return 'tag--cyan';
    if (t.includes('stealth') || t.includes('evasion') || t.includes('defense')) return 'tag--indigo';
    if (t.includes('recon'))                                       return 'tag--teal';
    if (t.includes('execut') || t.includes('collection'))         return 'tag--green';
    return 'tag--blue';
  }
}
