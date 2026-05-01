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
  showAddForm: boolean = false;
  totalHits: number = 0;
  message: string = '';
  messageType: string = '';

  newRule = {
    title: '',
    severity: 'medium',
    description: '',
    field: 'proto',
    value: '',
    matcher: 'equals',
    tags: [] as string[]
  };

  // Real NDR field definitions
  fieldOptions = [
    {
      value: 'proto',
      label: 'Protocol',
      description: 'Network protocol',
      examples: ['tcp', 'udp', 'icmp']
    },
    {
      value: 'src_ip',
      label: 'Source IP',
      description: 'IP address of the sender',
      examples: ['192.168.1.1', '10.0.0.0/8']
    },
    {
      value: 'dst_ip',
      label: 'Destination IP',
      description: 'IP address of the receiver',
      examples: ['8.8.8.8', '1.1.1.1']
    },
    {
      value: 'network_protocol',
      label: 'Application Protocol',
      description: 'Layer 7 protocol detected by Zeek',
      examples: ['dns', 'http', 'ssl', 'ssh', 'ftp', 'smtp']
    },
    {
      value: 'event_type',
      label: 'Event Type',
      description: 'Type of event from Suricata',
      examples: ['alert', 'flow', 'dns', 'http', 'tls']
    },
    {
      value: 'conn_state',
      label: 'Connection State',
      description: 'Zeek connection state code',
      examples: ['S0', 'REJ', 'SF', 'RSTO', 'RSTR']
    },
    {
      value: 'alert.category',
      label: 'Alert Category',
      description: 'Suricata alert category',
      examples: ['Malware', 'Exploit', 'Policy Violation']
    },
    {
      value: 'alert.signature',
      label: 'Alert Signature',
      description: 'Suricata rule signature name',
      examples: ['ET MALWARE', 'ET SCAN', 'ET POLICY']
    },
    {
      value: 'source',
      label: 'Data Source',
      description: 'Which sensor generated the event',
      examples: ['zeek', 'suricata']
    },
  ];

  // Connection state descriptions
  connStateHelp = [
    { state: 'S0', meaning: 'No reply — possible scan/drop' },
    { state: 'REJ', meaning: 'Connection rejected by target' },
    { state: 'SF', meaning: 'Normal established connection' },
    { state: 'RSTO', meaning: 'Originator sent RST' },
    { state: 'RSTR', meaning: 'Responder sent RST' },
    { state: 'OTH', meaning: 'No SYN seen, mid-connection' },
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

  showConnHelp: boolean = false;
  showFieldInfo: boolean = false;

  GavelIcon = Gavel;
  PlusIcon = Plus;
  EditIcon = Edit;
  TrashIcon = Trash2;
  PowerIcon = Power;
  RefreshIcon = RefreshCcw;
  XIcon = X;
  InfoIcon = Info;

  constructor(private api: Api, private cdr: ChangeDetectorRef) { }

  ngOnInit() {
    this.loadRules();
  }

  get selectedField() {
    return this.fieldOptions.find(f => f.value === this.newRule.field);
  }

  get selectedSeverity() {
    return this.severityOptions.find(s => s.value === this.newRule.severity);
  }

  loadRules() {
    this.loading = true;
    this.api.getRules().subscribe({
      next: (data: any[]) => {
        this.rules = data.map(r => ({
          name: r.title || 'Unknown',
          type: 'SIGMA',
          severity: (r.severity || 'medium').toUpperCase(),
          status: 'ACTIVE',
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

  saveRule() {
    if (!this.newRule.title || !this.newRule.value) {
      this.showMessage('Title and Value are required', 'error');
      return;
    }
    this.saving = true;

    this.api.createRule(this.newRule).subscribe({
      next: (data: any) => {
        this.saving = false;
        if (data.status === 'created') {
          // Auto reload rules — no restart needed!
          this.api.reloadRules().subscribe({
            next: (reload: any) => {
              this.showMessage(
                `✅ Rule "${this.newRule.title}" saved and activated! ${reload.count} rules now active.`,
                'success'
              );
              this.showAddForm = false;
              this.resetForm();
              setTimeout(() => this.loadRules(), 1000);
              this.cdr.detectChanges();
            }
          });
        } else {
          this.showMessage(data.message || 'Error', 'error');
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
      next: () => {
        this.showMessage(`Rule "${rule.name}" deleted`, 'success');
        this.loadRules();
      },
      error: () => this.showMessage('Failed to delete rule', 'error')
    });
  }

  toggleRule(rule: any) {
    rule.status = rule.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
    this.cdr.detectChanges();
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
    this.newRule = {
      title: '', severity: 'medium', description: '',
      field: 'proto', value: '', matcher: 'equals', tags: []
    };
    this.showConnHelp = false;
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