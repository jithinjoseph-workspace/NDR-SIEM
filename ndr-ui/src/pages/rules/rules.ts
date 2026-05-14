import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { LucideAngularModule, Gavel, Plus, Edit, Trash2, Power, RefreshCcw, X, Info } from 'lucide-angular';

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
      description: 'Type of event from Suricata',
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
      description: 'Zeek connection state code',
      examples: ['S0', 'REJ', 'SF', 'OTH', 'RSTO']
    },
    {
      value: 'network_protocol',
      label: 'Application Protocol',
      description: 'Layer 7 protocol detected by Zeek',
      examples: ['dns', 'http', 'ssl', 'ssh', 'ftp', 'smtp']
    },
    {
      value: 'alert.severity',
      label: 'Alert Severity',
      description: 'Suricata severity (1=high, 2=med, 3=low)',
      examples: ['1', '2', '3']
    },
    {
      value: 'alert.signature',
      label: 'Alert Signature',
      description: 'Suricata rule signature name',
      examples: ['ET MALWARE', 'ET SCAN', 'ET POLICY']
    },
    {
      value: 'alert.category',
      label: 'Alert Category',
      description: 'Suricata alert category',
      examples: ['Malware', 'Exploit', 'Policy Violation']
    },
    {
      value: 'log_source',
      label: 'Log Source (Zeek)',
      description: 'Zeek log type',
      examples: ['conn', 'dns', 'http', 'ssl', 'ssh']
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

  constructor(private api: Api, private cdr: ChangeDetectorRef) { }

  get selectedField() {
    return this.fieldOptions.find(f => f.value === this.ruleForm.field);
  }

  get selectedSeverity() {
    return this.severityOptions.find(s => s.value === this.ruleForm.severity);
  }

  get activeRulesCount() {
    return this.rules.filter(r => r.status === 'ACTIVE').length;
  }

  ngOnInit() { this.loadRules(); }

  loadRules() {
    this.loading = true;
    this.api.getRules().subscribe({
      next: (data: any[]) => {
        this.rules = data.map(r => ({
          name: r.title || 'Unknown',
          type: 'SIGMA',
          severity: (r.severity || 'medium').toUpperCase(),
          status: r.enabled ? 'ACTIVE' : 'INACTIVE',  // ← only this line changed
          id: r.id,
          description: r.description || '',
          tags: r.tags || [],
          conditions: r.conditions || 0,
        }));
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      }
    });

    this.api.getAlerts().subscribe({
      next: (data: any[]) => {
        this.totalHits = data.length;
        this.cdr.detectChanges();
      },
      error: () => { }
    });
  }
  openAddForm() {
    this.isEditing = false;
    this.editingId = '';
    this.resetForm();
    this.showForm = true;
  }

  openEditForm(rule: any) {
    this.isEditing = true;
    this.editingId = rule.id;
    this.showForm = true;

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
    console.log('Deleting rule id:', rule.id); // ← add this
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    this.api.deleteRule(rule.id).subscribe({
      next: () => {
        this.api.reloadRules().subscribe();
        this.showMessage(`Rule "${rule.name}" deleted`, 'success');
        this.api.reloadRules().subscribe({
          next: () => {
            // Remove from local array immediately — no need to fetch
            this.rules = this.rules.filter(r => r.id !== rule.id);
            this.showMessage(`Rule "${rule.name}" deleted`, 'success');
            this.cdr.detectChanges();
          }
        });
      },
      error: (err) => {
        console.log('Delete error:', err); // ← add this
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
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-400';
      case 'HIGH': return 'text-orange-400';
      case 'MEDIUM': return 'text-yellow-400';
      default: return 'text-blue-400';
    }
  }

  getSeverityBadgeClass(severity: string): string {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'HIGH': return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'MEDIUM': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      default: return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    }
  }
}
