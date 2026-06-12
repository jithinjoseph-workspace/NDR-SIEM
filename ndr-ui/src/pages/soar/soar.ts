import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import {
    LucideAngularModule,
    Zap, Play, Pause, Settings,
    CheckCircle, XCircle, Link,
    RefreshCw, ExternalLink, Plus,
    Trash2, Bell, Mail, Globe, Shield, Activity, ShieldAlert
} from 'lucide-angular';

@Component({
    selector: 'app-soar',
    standalone: true,
    imports: [CommonModule, LucideAngularModule, FormsModule],
    templateUrl: './soar.html',
    styleUrl: './soar.css'
})
export class Soar implements OnInit {
    ZapIcon = Zap;
    PlayIcon = Play;
    PauseIcon = Pause;
    SettingsIcon = Settings;
    CheckIcon = CheckCircle;
    XIcon = XCircle;
    LinkIcon = Link;
    RefreshIcon = RefreshCw;
    ExternalIcon = ExternalLink;
    PlusIcon = Plus;
    TrashIcon = Trash2;
    BellIcon = Bell;
    MailIcon = Mail;
    GlobeIcon = Globe;
    ShieldIcon = Shield;
    ActivityIcon = Activity;
    ShieldAlertIcon = ShieldAlert;

    activeTab: 'cases' | 'playbooks' | 'integrations' | 'activity' = 'cases';
    loading = false;

    // --- Cases ---
    cases: any[] = [];
    selectedCase: any = null;
    caseComments: any[] = [];
    newComment = '';
    loadingCase = false;

    // --- Playbooks ---
    playbooks: any[] = [];
    showNewPlaybook = false;
    pbName = '';
    pbDesc = '';
    pbCondField = 'score';
    pbCondOp = '>';
    pbCondValue = '75';
    pbActionType = 'slack';
    pbActionConfig: any = {};
    savingPb = false;
    pbError = '';

    // --- Integrations ---
    integrations: any[] = [];
    showNewIntegration = false;
    intType = 'slack';
    intName = '';
    intConfig: any = {};
    testingInt = false;
    testResult = '';
    savingInt = false;
    testingAll = false;
    testAllResults: any[] = [];

    // --- Activity Log ---
    runs: any[] = [];

    integrationTypes = [
        {
            type: 'slack', name: 'Slack', icon: '💬',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/...' }]
        },
        {
            type: 'teams', name: 'Microsoft Teams', icon: '🟦',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://outlook.office.com/webhook/...' }]
        },
        {
            type: 'discord', name: 'Discord', icon: '🎮',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://discord.com/api/webhooks/...' }]
        },
        {
            type: 'webhook', name: 'Custom Webhook', icon: '🔗',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://your-endpoint.com/alert' }]
        },
        {
            type: 'smtp', name: 'SMTP Email', icon: '📧',
            fields: [
                { key: 'smtp_host', label: 'SMTP Host', placeholder: 'smtp.gmail.com' },
                { key: 'smtp_port', label: 'SMTP Port', placeholder: '587' },
                { key: 'smtp_user', label: 'SMTP User', placeholder: 'user@domain.com' },
                { key: 'smtp_pass', label: 'SMTP Password', placeholder: 'password' },
                { key: 'from_addr', label: 'From Address', placeholder: 'alerts@domain.com' },
                { key: 'to_addr', label: 'Default To Address', placeholder: 'soc@domain.com' }
            ]
        }
    ];

    constructor(private api: Api, private cdr: ChangeDetectorRef) {}

    ngOnInit() {
        this.loadCases();
        this.loadPlaybooks();
        this.loadIntegrations();
        this.loadRuns();
    }

    // --- API Loaders ---
    loadCases() {
        this.api.getSoarCases().subscribe((res: any) => {
            if (res.status === 'success') {
                this.cases = res.data;
                this.cdr.detectChanges();
            }
        });
    }

    loadPlaybooks() {
        this.api.getNativePlaybooks().subscribe((res: any) => {
            if (res.status === 'success') {
                this.playbooks = res.data;
                this.cdr.detectChanges();
            }
        });
    }

    loadIntegrations() {
        this.api.getIntegrations().subscribe((res: any) => {
            this.integrations = res.integrations || [];
            this.cdr.detectChanges();
        });
    }

    loadRuns() {
        this.api.getSoarRuns().subscribe((res: any) => {
            if (res.status === 'success') {
                this.runs = res.data;
                this.cdr.detectChanges();
            }
        });
    }

    // --- Tab Switching ---
    switchTab(tab: 'cases' | 'playbooks' | 'integrations' | 'activity') {
        this.activeTab = tab;
        if (tab === 'cases') this.loadCases();
        if (tab === 'playbooks') this.loadPlaybooks();
        if (tab === 'integrations') this.loadIntegrations();
        if (tab === 'activity') this.loadRuns();
    }

    // --- Cases Logic ---
    openCase(c: any) {
        this.selectedCase = c;
        this.loadingCase = true;
        this.api.getSoarCaseComments(c.id).subscribe((res: any) => {
            if (res.status === 'success') {
                this.caseComments = res.data;
            }
            this.loadingCase = false;
            this.cdr.detectChanges();
        });
    }

    closeCaseModal() {
        this.selectedCase = null;
        this.caseComments = [];
    }

    updateCaseStatus(status: string) {
        if (!this.selectedCase) return;
        this.api.updateSoarCaseStatus(this.selectedCase.id, status).subscribe((res: any) => {
            if (res.status === 'success') {
                this.selectedCase.status = status;
                this.loadCases();
            }
        });
    }

    addComment() {
        if (!this.newComment.trim() || !this.selectedCase) return;
        this.api.addSoarCaseComment(this.selectedCase.id, this.newComment).subscribe((res: any) => {
            if (res.status === 'success') {
                this.newComment = '';
                this.openCase(this.selectedCase); // reload comments
            }
        });
    }

    getCaseColor(severity: string) {
        const s = (severity || '').toLowerCase();
        if (s === 'critical') return 'text-red-400 bg-red-500/10';
        if (s === 'high') return 'text-orange-400 bg-orange-500/10';
        if (s === 'medium') return 'text-yellow-400 bg-yellow-500/10';
        return 'text-blue-400 bg-blue-500/10';
    }

    // --- Playbooks Logic ---
    togglePlaybook(pb: any) {
        pb.enabled = pb.enabled === 1 ? 0 : 1;
        this.api.updateNativePlaybook(pb.id, {
            enabled: pb.enabled === 1,
            cond_field: pb.cond_field,
            cond_op: pb.cond_op,
            cond_value: pb.cond_value,
            action_type: pb.action_type,
            action_config: pb.action_config
        }).subscribe(() => this.loadPlaybooks());
    }

    deletePlaybook(pb: any) {
        if (confirm(`Delete playbook ${pb.name}?`)) {
            this.api.deleteNativePlaybook(pb.id).subscribe(() => this.loadPlaybooks());
        }
    }

    savePlaybook() {
        if (!this.pbName) {
            this.pbError = 'Name is required';
            return;
        }
        this.savingPb = true;
        this.pbError = '';

        const data = {
            name: this.pbName,
            description: this.pbDesc,
            enabled: true,
            cond_field: this.pbCondField,
            cond_op: this.pbCondOp,
            cond_value: this.pbCondValue,
            action_type: this.pbActionType,
            action_config: JSON.stringify(this.pbActionConfig) // Must send string
        };

        this.api.createNativePlaybook(data).subscribe({
            next: (res: any) => {
                this.savingPb = false;
                if (res.status === 'success') {
                    this.showNewPlaybook = false;
                    this.loadPlaybooks();
                } else {
                    this.pbError = res.message;
                }
            },
            error: (err) => {
                this.savingPb = false;
                this.pbError = 'Failed to create playbook';
            }
        });
    }

    initPlaybookModal() {
        this.showNewPlaybook = true;
        this.pbName = '';
        this.pbDesc = '';
        this.pbCondField = 'score';
        this.pbCondOp = '>';
        this.pbCondValue = '75';
        this.pbActionType = 'slack';
        this.pbActionConfig = {};
        this.pbError = '';
    }

    // --- Integrations Logic (Reused) ---
    getIntIcon(type: string): string {
        return this.integrationTypes.find(t => t.type === type)?.icon || '🔔';
    }

    get selectedIntType() {
        return this.integrationTypes.find(t => t.type === this.intType);
    }

    testIntegration() {
        this.testingInt = true;
        this.testResult = '';
        this.api.testIntegration({ type: this.intType, config: this.intConfig }).subscribe({
            next: (data: any) => {
                this.testingInt = false;
                this.testResult = data.message;
                this.cdr.detectChanges();
            },
            error: () => {
                this.testingInt = false;
                this.testResult = '❌ Connection failed';
                this.cdr.detectChanges();
            }
        });
    }

    saveIntegration() {
        this.savingInt = true;
        this.api.saveIntegration({
            name: this.intName || this.selectedIntType?.name,
            type: this.intType,
            config: this.intConfig
        }).subscribe({
            next: () => {
                this.savingInt = false;
                this.showNewIntegration = false;
                this.intConfig = {};
                this.intName = '';
                this.loadIntegrations();
            },
            error: () => {
                this.savingInt = false;
            }
        });
    }

    toggleIntegration(int: any) {
        int.enabled = !int.enabled;
        this.api.toggleIntegration({ id: int.id, enabled: int.enabled }).subscribe();
    }

    deleteIntegration(int: any) {
        if (!confirm(`Delete ${int.name}?`)) return;
        this.api.deleteIntegration({ id: int.id }).subscribe(() => this.loadIntegrations());
    }

    // --- Date Formatting ---
    formatDate(ts: any) {
        if (!ts) return 'N/A';
        const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
        return d.toLocaleString();
    }
}