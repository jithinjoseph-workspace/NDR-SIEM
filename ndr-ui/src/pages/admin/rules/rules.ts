import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef, ViewEncapsulation } from '@angular/core';
import { CommonModule, DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import {
  LucideAngularModule,
  Gavel, Plus, Edit, Trash2, Power, RefreshCcw, X, Info, Download, ChevronDown, Search,
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
export class AdminRules implements OnInit {
  rules: any[]         = [];
  filteredRules: any[] = [];
  displayCount         = 20;
  loading              = true;
  saving               = false;
  syncing              = false;
  isSearching          = false;
  showForm             = false;
  isEditing            = false;
  editingId            = '';
  totalHits            = 0;
  searchQuery          = '';
  message              = '';
  messageType          = '';
  showFieldInfo        = false;
  showConnHelp         = false;

  get displayedRules() { return this.filteredRules.slice(0, this.displayCount); }
  get hasMore()        { return this.displayCount < this.filteredRules.length; }
  get shownCount()     { return Math.min(this.displayCount, this.filteredRules.length); }

  ruleForm = {
    title: '', severity: 'medium', description: '',
    field: 'event_type', value: '', matcher: 'equals', tags: [] as string[],
  };

  fieldOptions = [
    { value: 'event_type',        label: 'Event Type',             examples: ['alert', 'flow', 'dns', 'http'] },
    { value: 'proto',             label: 'Protocol',               examples: ['tcp', 'udp', 'icmp'] },
    { value: 'source_ip',         label: 'Source IP',              examples: ['10.0.2.15', '192.168.1.1'] },
    { value: 'dest_ip',           label: 'Destination IP',         examples: ['8.8.8.8', '93.184.216.34'] },
    { value: 'conn_state',        label: 'Connection State',       examples: ['S0', 'REJ', 'SF', 'OTH'] },
    { value: 'network_protocol',  label: 'App Protocol',           examples: ['dns', 'http', 'ssl', 'ssh'] },
    { value: 'alert.severity',    label: 'Alert Severity',         examples: ['1', '2', '3'] },
    { value: 'alert.signature',   label: 'Alert Signature',        examples: ['ET MALWARE', 'ET SCAN'] },
    { value: 'alert.category',    label: 'Alert Category',         examples: ['Malware', 'Exploit'] },
    { value: 'log_source',        label: 'Log Source',             examples: ['conn', 'dns', 'http'] },
    { value: 'Image',             label: 'Process Image',          examples: ['/bin/bash', '/tmp/malware'] },
    { value: 'CommandLine',       label: 'Command Line',           examples: ['curl http://', 'nc -e /bin/sh'] },
    { value: 'ParentImage',       label: 'Parent Process',         examples: ['/bin/bash', '/usr/sbin/sshd'] },
    { value: 'TargetFilename',    label: 'Target Filename',        examples: ['/etc/crontab', '/tmp/'] },
    { value: 'DestinationIp',     label: 'Dest IP (Endpoint)',     examples: ['10.0.0.1', '8.8.8.8'] },
    { value: 'DestinationPort',   label: 'Dest Port (Endpoint)',   examples: ['4444', '1337', '443'] },
    { value: 'User',              label: 'User',                   examples: ['root', 'www-data'] },
    { value: 'type',              label: 'Auditd Record Type',     examples: ['EXECVE', 'SYSCALL'] },
  ];

  connStateHelp = [
    { state: 'S0',   meaning: 'No reply — possible scan' },
    { state: 'REJ',  meaning: 'Connection rejected' },
    { state: 'SF',   meaning: 'Normal connection' },
    { state: 'OTH',  meaning: 'Mid-stream, no SYN' },
    { state: 'RSTO', meaning: 'Originator sent RST' },
    { state: 'RSTR', meaning: 'Responder sent RST' },
  ];

  matcherOptions = [
    { value: 'equals',     label: 'Equals',      description: 'Exact match' },
    { value: 'contains',   label: 'Contains',     description: 'Partial match' },
    { value: 'startswith', label: 'Starts With',  description: 'Prefix match' },
    { value: 'endswith',   label: 'Ends With',    description: 'Suffix match' },
    { value: 're',         label: 'Regex',        description: 'Pattern match' },
  ];

  severityOptions = [
    { value: 'critical', label: 'Critical' },
    { value: 'high',     label: 'High' },
    { value: 'medium',   label: 'Medium' },
    { value: 'low',      label: 'Low' },
  ];

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

  GavelIcon   = Gavel;
  SearchIcon  = Search;
  PlusIcon    = Plus;
  EditIcon    = Edit;
  TrashIcon   = Trash2;
  PowerIcon   = Power;
  RefreshIcon = RefreshCcw;
  XIcon       = X;
  InfoIcon    = Info;
  DownloadIcon = Download;
  ChevronIcon = ChevronDown;

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  get activeRulesCount() { return this.rules.filter(r => r.status === 'ACTIVE').length; }
  get selectedField()    { return this.fieldOptions.find(f => f.value === this.ruleForm.field); }

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
          error: () => {},
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

  syncCommunityRules() {
    this.syncing = true;
    this.api.syncCommunityRules().subscribe({
      next: (res: any) => {
        this.syncing = false;
        this.showMsg(res.status === 'already_running'
          ? res.message || 'Sync already in progress'
          : 'Sync started — refresh in ~60 seconds', 'success');
        if (res.status !== 'already_running') setTimeout(() => this.loadRules(), 60_000);
      },
      error: (err: any) => {
        this.syncing = false;
        this.showMsg(err?.error?.error || 'Sync failed', 'error');
      },
    });
  }

  openAddForm() {
    this.isEditing = false; this.editingId = '';
    this.resetForm(); this.showForm = true;
  }

  openEditForm(rule: any) {
    this.isEditing = true; this.editingId = rule.id; this.showForm = true;
    this.api.getRuleById(rule.id).subscribe({
      next: (data: any) => {
        this.ruleForm = {
          title: data.title || rule.name, severity: data.severity || 'medium',
          description: data.description || '', field: data.field || 'event_type',
          value: data.value || '', matcher: data.matcher || 'equals', tags: data.tags || [],
        };
        this.cdr.detectChanges();
      },
      error: () => {
        this.ruleForm = { title: rule.name, severity: rule.severity.toLowerCase(),
          description: rule.description || '', field: 'event_type',
          value: '', matcher: 'equals', tags: rule.tags || [] };
        this.cdr.detectChanges();
      },
    });
  }

  applyTemplate(t: any) {
    this.ruleForm = { ...this.ruleForm, field: t.field, value: t.value,
      matcher: t.matcher, title: t.title, severity: t.severity, description: t.description };
  }

  saveRule() {
    if (!this.ruleForm.title || !this.ruleForm.value) {
      this.showMsg('Title and Value are required', 'error'); return;
    }
    this.saving = true;
    if (this.isEditing) {
      this.api.deleteRule(this.editingId).subscribe({
        next: () => this.createNewRule(), error: () => this.createNewRule(),
      });
    } else { this.createNewRule(); }
  }

  createNewRule() {
    this.api.createRule(this.ruleForm).subscribe({
      next: (data: any) => {
        this.saving = false;
        if (data.status === 'created') {
          this.api.reloadRules().subscribe({
            next: (reload: any) => {
              const action = this.isEditing ? 'updated' : 'created';
              this.showMsg(`Rule "${this.ruleForm.title}" ${action}. ${reload.count} active.`, 'success');
              this.showForm = false; this.resetForm(); this.loadRules();
              this.cdr.detectChanges();
            },
          });
        } else { this.showMsg(data.message || 'Error', 'error'); this.saving = false; }
        this.cdr.detectChanges();
      },
      error: () => { this.saving = false; this.showMsg('Failed to save rule', 'error'); this.cdr.detectChanges(); },
    });
  }

  deleteRule(rule: any) {
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    this.api.deleteRule(rule.id).subscribe({
      next: () => this.api.reloadRules().subscribe({
        next: () => {
          this.rules = this.rules.filter(r => r.id !== rule.id);
          this.showMsg(`Rule "${rule.name}" deleted`, 'success');
          this.cdr.detectChanges();
        },
      }),
      error: () => this.showMsg('Failed to delete rule', 'error'),
    });
  }

  toggleRule(rule: any) {
    const enable = rule.status !== 'ACTIVE';
    this.api.toggleRule(rule.id, enable).subscribe({
      next: (data: any) => {
        rule.status = enable ? 'ACTIVE' : 'INACTIVE';
        this.showMsg(`Rule "${rule.name}" ${enable ? 'enabled' : 'disabled'} — ${data.active_rules} active`, 'success');
        this.cdr.detectChanges();
      },
      error: () => this.showMsg('Failed to toggle rule', 'error'),
    });
  }

  showMsg(msg: string, type: string) {
    this.message = msg; this.messageType = type;
    setTimeout(() => { this.message = ''; this.cdr.detectChanges(); }, 6000);
  }

  resetForm() {
    this.ruleForm = { title: '', severity: 'medium', description: '',
      field: 'event_type', value: '', matcher: 'equals', tags: [] };
    this.showConnHelp = false; this.showFieldInfo = false;
    this.isEditing = false; this.editingId = '';
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
