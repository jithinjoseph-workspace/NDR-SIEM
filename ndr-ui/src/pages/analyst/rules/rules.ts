import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { LucideAngularModule, Gavel, Plus, Edit, Trash2, Power, RefreshCcw, X, Info, Download, ShieldCheck, Activity, Target } from 'lucide-angular';

@Component({
  selector: 'app-rules',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule],
  templateUrl: './rules.html',
  styleUrl: './rules.css'
})
export class Rules implements OnInit {
  rules: any[] = [];
  loading: boolean = true;
  saving: boolean = false;
  showForm: boolean = false;
  isEditing: boolean = false;
  editingId: string = '';
  totalHits: number = 0;
  message: string = '';
  messageType: string = '';
  showConnHelp: boolean = false;
  showFieldInfo: boolean = false;

  ruleForm = {
    title: '',
    severity: 'medium',
    description: '',
    field: 'event_type',
    value: '',
    matcher: 'equals',
    tags: [] as string[]
  };

  // CORRECT field names matching normalizer get_field()
  fieldOptions = [
    {
      value: 'event_type',
      label: 'Event Type',
      description: 'Type of event from Agent-S',
      examples: ['alert', 'flow', 'dns', 'http', 'tls', 'quic']
    },
    {
      value: 'proto',
      label: 'Protocol',
      description: 'Network protocol (lowercase)',
      examples: ['tcp', 'udp', 'icmp', 'ipv6-icmp']
    },
    {
      value: 'source_ip',
      label: 'Source IP',
      description: 'IP address of the sender',
      examples: ['10.0.2.15', '192.168.1.1']
    },
    {
      value: 'dest_ip',
      label: 'Destination IP',
      description: 'IP address of the receiver',
      examples: ['93.184.216.34', '8.8.8.8']
    },
    {
      value: 'conn_state',
      label: 'Connection State',
      description: 'Agent-Z connection state code',
      examples: ['S0', 'REJ', 'SF', 'OTH', 'RSTO']
    },
    {
      value: 'network_protocol',
      label: 'Application Protocol',
      description: 'Layer 7 protocol detected by Agent-Z',
      examples: ['dns', 'http', 'ssl', 'ssh', 'ftp', 'smtp']
    },
    {
      value: 'alert.severity',
      label: 'Alert Severity',
      description: 'Agent-S severity (1=high, 2=med, 3=low)',
      examples: ['1', '2', '3']
    },
    {
      value: 'alert.signature',
      label: 'Alert Signature',
      description: 'Agent-S rule signature name',
      examples: ['ET MALWARE', 'ET SCAN', 'ET POLICY']
    },
    {
      value: 'alert.category',
      label: 'Alert Category',
      description: 'Agent-S alert category',
      examples: ['Malware', 'Exploit', 'Policy Violation']
    },
    {
      value: 'log_source',
      label: 'Log Source (Agent-Z)',
      description: 'Agent-Z log type',
      examples: ['conn', 'dns', 'http', 'ssl', 'ssh']
    },
    // ── Linux endpoint fields (auditd) ──────────────────────────────────
    {
      value: 'Image',
      label: 'Process Image',
      description: 'Full path of the executed binary',
      examples: ['/bin/bash', '/usr/bin/curl', '/tmp/malware', '/bin/sh']
    },
    {
      value: 'CommandLine',
      label: 'Command Line',
      description: 'Full command including arguments',
      examples: ['curl http://', 'chmod +x', 'wget ', 'nc -e /bin/sh']
    },
    {
      value: 'ParentImage',
      label: 'Parent Process',
      description: 'Path of the parent process that spawned this one',
      examples: ['/bin/bash', '/usr/sbin/sshd', '/bin/sh']
    },
    {
      value: 'TargetFilename',
      label: 'Target Filename',
      description: 'File path written or modified',
      examples: ['/etc/crontab', '/root/.ssh/', '/tmp/', '/etc/passwd']
    },
    {
      value: 'DestinationIp',
      label: 'Destination IP (Endpoint)',
      description: 'Outbound connection destination from a Linux process',
      examples: ['10.0.0.1', '192.168.', '8.8.8.8']
    },
    {
      value: 'DestinationPort',
      label: 'Destination Port (Endpoint)',
      description: 'Outbound connection port from a Linux process',
      examples: ['4444', '1337', '31337', '443']
    },
    {
      value: 'User',
      label: 'User',
      description: 'Linux user account running the process',
      examples: ['root', 'www-data', 'nobody']
    },
    {
      value: 'type',
      label: 'Auditd Record Type',
      description: 'Type of auditd event record',
      examples: ['EXECVE', 'SYSCALL', 'PATH', 'SOCKADDR']
    },
  ];

  connStateHelp = [
    { state: 'S0', meaning: 'No reply - possible scan' },
    { state: 'REJ', meaning: 'Connection rejected' },
    { state: 'SF', meaning: 'Normal connection' },
    { state: 'OTH', meaning: 'Mid-stream, no SYN' },
    { state: 'RSTO', meaning: 'Originator sent RST' },
    { state: 'RSTR', meaning: 'Responder sent RST' },
  ];

  matcherOptions = [
    { value: 'equals', label: 'Equals', description: 'Exact match' },
    { value: 'contains', label: 'Contains', description: 'Partial match' },
    { value: 'startswith', label: 'Starts With', description: 'Prefix match' },
    { value: 'endswith', label: 'Ends With', description: 'Suffix match' },
    { value: 're', label: 'Regex', description: 'Pattern match' },
  ];

  severityOptions = [
    { value: 'critical', label: 'Critical', color: 'text-red-400', description: 'Immediate action required' },
    { value: 'high', label: 'High', color: 'text-orange-400', description: 'Serious threat' },
    { value: 'medium', label: 'Medium', color: 'text-yellow-400', description: 'Suspicious activity' },
    { value: 'low', label: 'Low', color: 'text-blue-400', description: 'Informational' },
  ];

  GavelIcon = Gavel;
  PlusIcon = Plus;
  EditIcon = Edit;
  TrashIcon = Trash2;
  PowerIcon = Power;
  RefreshIcon = RefreshCcw;
  XIcon = X;
  InfoIcon = Info;
  DownloadIcon = Download;
  ShieldCheckIcon = ShieldCheck;
  ActivityIcon = Activity;
  TargetIcon = Target;

  syncing = false;
  categoryFilter: string = '';
  severityFilter: string = '';
  activeTab: 'all' | 'agent-z' | 'agent-s' = 'all';
  agentSRules: any[] = [];

  // ── Pagination (Agent-Z / SIGMA rules — the large set) ─────────────────────
  pageSize = 20;
  rulesOffset = 0;
  rulesTotal = 0;
  rulesActiveTotal = 0;
  loadingMore = false;
  private hitCountsCache: { [ruleName: string]: number } = {};

  get hasMoreRules(): boolean {
    return this.rules.length < this.rulesTotal;
  }

  // ── Search (checks what's already loaded first; falls back to a DB query
  //    only when nothing loaded matches, so we can say for sure whether a
  //    rule exists at all rather than just "not in the first page") ─────────
  searchTerm = '';
  searching = false;
  dbSearchActive = false;
  dbSearchChecked = false;
  dbSearchResults: any[] = [];
  private searchDebounce: any;

  get topCategories(): { tag: string; label: string; count: number }[] {
    const counts: { [key: string]: number } = {};
    for (const rule of this.rules) {
      for (const tag of (rule.tags || [])) {
        if (/^attack\.t\d+/i.test(tag)) continue;
        if (!tag.startsWith('attack.')) continue;
        counts[tag] = (counts[tag] || 0) + 1;
      }
    }
    return Object.entries(counts)
      .map(([tag, count]) => ({ tag, label: this.catLabel(tag), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 9);
  }

  get severityCounts(): { [key: string]: number } {
    const counts: { [key: string]: number } = {};
    for (const rule of this.rules) {
      const s = (rule.severity || 'MEDIUM').toUpperCase();
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }

  get allRules(): any[] {
    if (this.activeTab === 'agent-z') return this.rules;
    if (this.activeTab === 'agent-s') return this.agentSRules;
    return [...this.rules, ...this.agentSRules];
  }

  get displayRules(): any[] {
    if (this.dbSearchActive) return this.dbSearchResults;
    const term = this.searchTerm.trim().toLowerCase();
    return this.allRules.filter(rule => {
      const catOk = !this.categoryFilter || (rule.tags || []).includes(this.categoryFilter);
      const sevOk = !this.severityFilter || rule.severity.toUpperCase() === this.severityFilter;
      const searchOk = !term
        || (rule.name || '').toLowerCase().includes(term)
        || (rule.tags || []).some((t: string) => t.toLowerCase().includes(term));
      return catOk && sevOk && searchOk;
    });
  }

  setCategory(tag: string) {
    this.categoryFilter = this.categoryFilter === tag ? '' : tag;
  }

  setSeverity(sev: string) {
    this.severityFilter = this.severityFilter === sev ? '' : sev;
  }

  clearFilters() {
    this.categoryFilter = '';
    this.severityFilter = '';
  }

  private catLabel(tag: string): string {
    const name = tag.replace('attack.', '').replace(/-/g, ' ');
    return name.charAt(0).toUpperCase() + name.slice(1);
  }

  constructor(
    private api: Api,
    private auth: AuthService,
    private cdr: ChangeDetectorRef,
  ) { }

  get isAdmin() { return this.auth.isAdmin(); }

  syncCommunityRules() {
    this.syncing = true;
    this.api.syncCommunityRules().subscribe({
      next: (res: any) => {
        this.syncing = false;
        if (res.status === 'already_running') {
          this.showMessage(res.message || 'Sync already in progress — check back in a minute', 'success');
        } else {
          this.showMessage('Sync started in background — refresh rules in a minute', 'success');
          setTimeout(() => this.loadRules(), 60_000);
        }
      },
      error: (err: any) => {
        this.syncing = false;
        this.showMessage(err?.error?.error || err?.error?.message || 'Sync failed — check engine connectivity', 'error');
      },
    });
  }

  get selectedField() {
    return this.fieldOptions.find(f => f.value === this.ruleForm.field);
  }

  get selectedSeverity() {
    return this.severityOptions.find(s => s.value === this.ruleForm.severity);
  }

  get activeRulesCount() {
    // rulesActiveTotal comes from the backend (X-Active-Count) so this stays
    // correct even though only one page of `rules` is actually loaded.
    return this.rulesActiveTotal + this.agentSRules.filter(r => r.status === 'ACTIVE').length;
  }

  ngOnInit() { this.loadRules(); }

  loadRules() {
    this.rules = [];
    this.rulesOffset = 0;
    this.rulesTotal = 0;
    this.rulesActiveTotal = 0;
    this.dbSearchActive = false;
    this.dbSearchChecked = false;

    this.fetchRulesPage(false);

    // Hit counts are a cheap aggregate over ALL rules (not paginated) —
    // fetch once, cache it, and apply to whichever page(s) get loaded.
    this.api.getRuleHitCounts().subscribe({
      next: (hitCounts: { [ruleName: string]: number }) => {
        this.hitCountsCache = hitCounts;
        this.totalHits = Object.values(hitCounts).reduce((a, b) => a + b, 0)
          + this.agentSRules.reduce((s: number, r: any) => s + r.hits, 0);
        this.rules = this.rules.map(r => ({ ...r, hits: hitCounts[r.name] || 0 }));
        this.cdr.detectChanges();
      },
      error: () => { }
    });

    // Load Agent-S fired rules from ndr_hits.sigma_hits — a small set (single
    // digits typically), so no pagination needed here.
    this.api.getFiredRules().subscribe({
      next: (r: any) => {
        const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        this.agentSRules = (r.rules ?? [])
          .filter((x: any) => x.name && !UUID_RE.test(x.name))  // exclude Sigma UUIDs — those appear in sigma rules
          .map((x: any) => ({
            name: x.name,
            type: 'Agent-S',
            severity: (x.severity || 'HIGH').toUpperCase(),
            status: 'ACTIVE',
            id: x.name,
            description: 'Agent-S detection rule (managed by the sensor)',
            tags: [],
            conditions: 0,
            hits: x.hit_count || 0,
          }));
        this.totalHits = this.totalHits + this.agentSRules.reduce((s: number, r: any) => s + r.hits, 0);
        this.cdr.detectChanges();
      },
      error: () => {}
    });
  }

  private mapAgentZRule(r: any): any {
    return {
      name: r.title || 'Unknown',
      type: 'Agent-Z',
      severity: (r.severity || 'medium').toUpperCase(),
      status: r.enabled ? 'ACTIVE' : 'INACTIVE',
      id: r.id,
      description: r.description || '',
      tags: r.tags || [],
      conditions: r.conditions || 0,
      hits: this.hitCountsCache[r.title] || 0,
    };
  }

  private fetchRulesPage(append: boolean) {
    if (append) this.loadingMore = true; else this.loading = true;
    this.api.getRulesPage(this.pageSize, this.rulesOffset).subscribe({
      next: (res) => {
        const mapped = res.rules.map((r: any) => this.mapAgentZRule(r));
        this.rules = append ? [...this.rules, ...mapped] : mapped;
        this.rulesOffset = this.rules.length;
        this.rulesTotal = res.total;
        this.rulesActiveTotal = res.activeTotal;
        this.loading = false;
        this.loadingMore = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.loadingMore = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadMoreRules() {
    if (this.loadingMore || !this.hasMoreRules) return;
    this.fetchRulesPage(true);
  }

  // ── Search: filter what's loaded first; only hit the backend when that
  // comes up empty, so we can tell the analyst whether the rule genuinely
  // doesn't exist or just isn't in the pages fetched so far. ────────────────
  onSearchInput() {
    clearTimeout(this.searchDebounce);
    this.dbSearchActive = false;
    this.dbSearchChecked = false;
    const term = this.searchTerm.trim();
    if (!term) return;
    this.searchDebounce = setTimeout(() => this.runSearch(term), 350);
  }

  private runSearch(term: string) {
    const lower = term.toLowerCase();
    const localMatch = this.allRules.some(r =>
      (r.name || '').toLowerCase().includes(lower) ||
      (r.tags || []).some((t: string) => t.toLowerCase().includes(lower))
    );
    if (localMatch) return; // already covered by displayRules' client-side filter

    this.searching = true;
    this.api.searchRules(term).subscribe({
      next: (res: any[]) => {
        this.searching = false;
        this.dbSearchChecked = true;
        this.dbSearchResults = (res || []).map(r => this.mapAgentZRule(r));
        this.dbSearchActive = true;
        this.cdr.detectChanges();
      },
      error: () => {
        this.searching = false;
        this.dbSearchChecked = true;
        this.dbSearchResults = [];
        this.dbSearchActive = true;
        this.cdr.detectChanges();
      }
    });
  }

  clearSearch() {
    this.searchTerm = '';
    this.dbSearchActive = false;
    this.dbSearchChecked = false;
    this.dbSearchResults = [];
  }

  openAddForm() {
    this.isEditing = false;
    this.editingId = '';
    this.resetForm();
    this.showForm = true;
    setTimeout(() => {
      document.querySelector('.rules-header')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);
  }

  openEditForm(rule: any) {
    this.isEditing = true;
    this.editingId = rule.id;
    this.showForm = true;
    setTimeout(() => {
      document.querySelector('.rules-header')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);

    // Load full rule details from API
    this.api.getRuleById(rule.id).subscribe({
      next: (data: any) => {
        this.ruleForm = {
          title: data.title || rule.name,
          severity: data.severity || 'medium',
          description: data.description || '',
          field: data.field || 'event_type',
          value: data.value || '',
          matcher: data.matcher || 'equals',
          tags: data.tags || []
        };
        this.cdr.detectChanges();
      },
      error: () => {
        // Fallback to basic info
        this.ruleForm = {
          title: rule.name,
          severity: rule.severity.toLowerCase(),
          description: rule.description || '',
          field: 'event_type',
          value: '',
          matcher: 'equals',
          tags: rule.tags || []
        };
        this.cdr.detectChanges();
      }
    });
  }
  saveRule() {
    if (!this.ruleForm.title || !this.ruleForm.value) {
      this.showMessage('Title and Value are required', 'error');
      return;
    }
    this.saving = true;

    if (this.isEditing) {
      // Delete old rule first then create new
      this.api.deleteRule(this.editingId).subscribe({
        next: () => this.createNewRule(),
        error: () => {
          // Even if delete fails, try creating
          this.createNewRule();
        }
      });
    } else {
      this.createNewRule();
    }
  }

  createNewRule() {
    this.api.createRule(this.ruleForm).subscribe({
      next: (data: any) => {
        this.saving = false;
        if (data.status === 'created') {
          // Hot reload
          this.api.reloadRules().subscribe({
            next: (reload: any) => {
              const action = this.isEditing ? 'updated' : 'created';
              this.showMessage(
                `Rule "${this.ruleForm.title}" ${action}. ${reload.count} rules active.`,
                'success'
              );
              this.showForm = false;
              this.resetForm();
              this.loadRules();
              this.cdr.detectChanges();
            }
          });
        } else {
          this.showMessage(data.message || 'Error', 'error');
          this.saving = false;
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.saving = false;
        this.showMessage('Failed to save rule', 'error');
        this.cdr.detectChanges();
      }
    });
  }

  deleteRule(rule: any) {
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    this.api.deleteRule(rule.id).subscribe({
      next: () =>
        this.api.reloadRules().subscribe({
          next: () => {
            // Remove from local array immediately — no need to fetch
            this.rules = this.rules.filter(r => r.id !== rule.id);
            this.showMessage(`Rule "${rule.name}" deleted`, 'success');
            this.cdr.detectChanges();
          }
        }),
      error: () => {
        this.showMessage('Failed to delete rule', 'error');
      }
    });
  }

  toggleRule(rule: any) {
    const newEnabled = rule.status !== 'ACTIVE';
    this.api.toggleRule(rule.id, newEnabled).subscribe({
      next: (data: any) => {
        rule.status = newEnabled ? 'ACTIVE' : 'INACTIVE';
        this.showMessage(
          `Rule "${rule.name}" ${newEnabled ? 'enabled' : 'disabled'} - ${data.active_rules} rules active`,
          'success'
        );
        this.cdr.detectChanges();
      },
      error: () => this.showMessage('Failed to toggle rule', 'error')
    });
  }

  showMessage(msg: string, type: string) {
    this.message = msg;
    this.messageType = type;
    setTimeout(() => {
      this.message = '';
      this.cdr.detectChanges();
    }, 6000);
  }

  resetForm() {
    this.ruleForm = {
      title: '', severity: 'medium', description: '',
      field: 'event_type', value: '', matcher: 'equals', tags: []
    };
    this.showConnHelp = false;
    this.isEditing = false;
    this.editingId = '';
  }

  getPlaceholder(): string {
    return this.selectedField?.examples?.[0] || 'Enter value';
  }

  getSeverityClass(severity: string): string {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'yaml-sev yaml-sev-critical';
      case 'high':     return 'yaml-sev yaml-sev-high';
      case 'medium':   return 'yaml-sev yaml-sev-medium';
      default:         return 'yaml-sev yaml-sev-low';
    }
  }

  getSeverityBadgeClass(severity: string): string {
    return 'sev-badge sev-' + (severity || 'low').toLowerCase();
  }

  sanitizeRuleName(name: string): string {
    return (name || '')
      .replace(/\bSURICATA\b/gi, 'Agent-S')
      .replace(/\bZEEK\b/gi, 'Agent-Z');
  }
}
