import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { ArkimeService } from '../../services/arkime/arkime';
import {
    LucideAngularModule,
    Zap, Play, Pause, Settings,
    CheckCircle, XCircle, Link,
    RefreshCw, ExternalLink, Plus,
    Trash2, Bell, Mail, Globe, Shield, Activity, ShieldAlert
} from 'lucide-angular';
import { AuthService } from '../../services/auth/auth';
import { SensorScopeBanner } from '../../components/sensor-scope-banner/sensor-scope-banner';

@Component({
    selector: 'app-soar',
    standalone: true,
    imports: [CommonModule, LucideAngularModule, FormsModule, SensorScopeBanner],
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
    editingPbId: string | null = null;
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
    editingIntId: string | null = null;
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
            type: 'slack', name: 'Slack', abbr: 'SLK',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/...', type: 'text' }]
        },
        {
            type: 'teams', name: 'Microsoft Teams', abbr: 'TMS',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://outlook.office.com/webhook/...', type: 'text' }]
        },
        {
            type: 'discord', name: 'Discord', abbr: 'DSC',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://discord.com/api/webhooks/...', type: 'text' }]
        },
        {
            type: 'webhook', name: 'Custom Webhook', abbr: 'WHK',
            fields: [{ key: 'webhook_url', label: 'Endpoint URL', placeholder: 'https://your-endpoint.com/alert', type: 'text' }]
        },
        {
            type: 'smtp', name: 'SMTP Email', abbr: 'EML',
            fields: [
                { key: 'smtp_host', label: 'SMTP Host', placeholder: 'smtp.gmail.com', type: 'text' },
                { key: 'smtp_port', label: 'SMTP Port', placeholder: '587', type: 'text' },
                { key: 'smtp_user', label: 'Username', placeholder: 'user@domain.com', type: 'text' },
                { key: 'smtp_pass', label: 'Password', placeholder: '••••••••', type: 'password' },
                { key: 'from_addr', label: 'From Address', placeholder: 'alerts@domain.com', type: 'text' },
                { key: 'to_addr', label: 'Default Recipient', placeholder: 'soc@domain.com', type: 'text' }
            ]
        }
    ];
    evidenceLoading = false;
    liveEvidence: any = null;

    /** Sensor IDs this user is scoped to (from JWT). */
    sensorIds: string[] = [];

    constructor(private api: Api, private arkime: ArkimeService, private cdr: ChangeDetectorRef, private auth: AuthService) {}

    ngOnInit() {
        this.sensorIds = this.auth.getSensorIds();
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
        this.liveEvidence = null;
        this.loadingCase = true;

        this.api.getSoarCaseComments(c.id).subscribe((res: any) => {
            if (res.status === 'success') {
                this.caseComments = res.data;
            }
            this.loadingCase = false;
            this.cdr.detectChanges();
        });

        // Auto-load live evidence for any case that has a community_id
        if (c.community_id) {
            this.evidenceLoading = true;
            const cid = c.community_id;

            // Fetch PCAP sessions + NDR events in parallel
            this.arkime.getSessions({ cid, limit: 10 }).subscribe((pcap: any) => {
                this.liveEvidence = this.liveEvidence || {};
                this.liveEvidence.pcap_sessions = pcap.sessions || [];
                this.liveEvidence.pcap_total = pcap.total || pcap.sessions?.length || 0;
                this.evidenceLoading = false;
                this.cdr.detectChanges();
            });

            this.api.getEventsByCid(cid).subscribe((res: any) => {
                this.liveEvidence = this.liveEvidence || {};
                this.liveEvidence.ndr_events = res.events || [];
                this.cdr.detectChanges();
            });
        }
    }

    formatTs(ts: number): string {
        if (!ts) return '-';
        return new Date(ts * 1000).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    formatPcapTime(ms: number): string {
        if (!ms) return '-';
        return new Date(ms).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    closeCaseModal() {
        this.selectedCase = null;
        this.caseComments = [];
        this.liveEvidence = null;
        this.evidenceLoading = false;
    }

    updateCaseStatus(status: string) {
        if (!this.selectedCase) return;
        this.api.updateSoarCaseStatus(this.selectedCase.id, status).subscribe({
            next: (res: any) => {
                if (res.status === 'success') {
                    this.selectedCase.status = status;
                    this.cdr.detectChanges();
                    this.loadCases();
                } else {
                    console.error('Status update failed:', res);
                    alert('Update failed: ' + res.message);
                }
            },
            error: (err) => {
                console.error('Status update API error:', err);
                alert('API error updating status: ' + (err.error?.message || err.message));
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

    // --- Condition Helpers ---
    get condOps(): { value: string; label: string }[] {
        switch (this.pbCondField) {
            case 'score':
                return [
                    { value: '>',  label: '>'  },
                    { value: '>=', label: '>=' },
                    { value: '<',  label: '<'  },
                    { value: '<=', label: '<=' },
                    { value: '==', label: '==' },
                ];
            case 'severity':
            case 'src_country':
            case 'sigma_tag':
                return [
                    { value: '==',       label: '=='       },
                    { value: 'contains', label: 'contains' },
                ];
            case 'threat_intel':
            default:
                return [{ value: '==', label: '==' }];
        }
    }

    get condValueType(): 'text' | 'severity' | 'bool' {
        if (this.pbCondField === 'severity')     return 'severity';
        if (this.pbCondField === 'threat_intel') return 'bool';
        return 'text';
    }

    onCondFieldChange() {
        this.pbCondOp = this.condOps[0].value;
        if (this.pbCondField === 'threat_intel') {
            this.pbCondValue = 'true';
        } else if (this.pbCondField === 'severity') {
            this.pbCondValue = 'HIGH';
        } else {
            this.pbCondValue = '75';
        }
    }

    // --- Playbooks Logic ---
    togglePlaybook(pb: any) {
        pb.enabled = pb.enabled === 1 ? 0 : 1;
        this.api.updateNativePlaybook(pb.id, {
            name: pb.name,
            description: pb.description,
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
            action_config: JSON.stringify(this.pbActionConfig)
        };

        const request$ = this.editingPbId
            ? this.api.updateNativePlaybook(this.editingPbId, data)
            : this.api.createNativePlaybook(data);

        request$.subscribe({
            next: (res: any) => {
                this.savingPb = false;
                if (res.status === 'success') {
                    this.showNewPlaybook = false;
                    this.editingPbId = null;
                    this.loadPlaybooks();
                } else {
                    this.pbError = res.message;
                    this.cdr.detectChanges();
                }
            },
            error: () => {
                this.savingPb = false;
                this.pbError = this.editingPbId ? 'Failed to update playbook' : 'Failed to create playbook';
                this.cdr.detectChanges();
            }
        });
    }

    initPlaybookModal() {
        this.editingPbId = null;
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

    openEditPlaybook(pb: any) {
        this.editingPbId = pb.id;
        this.showNewPlaybook = true;
        this.pbName = pb.name;
        this.pbDesc = pb.description;
        this.pbCondField = pb.cond_field;
        this.pbCondOp = pb.cond_op;
        this.pbCondValue = pb.cond_value;
        this.pbActionType = pb.action_type;
        try {
            this.pbActionConfig = typeof pb.action_config === 'string'
                ? JSON.parse(pb.action_config)
                : (pb.action_config || {});
        } catch {
            this.pbActionConfig = {};
        }
        this.pbError = '';
    }

    // --- Integrations Logic (Reused) ---
    getIntAbbr(type: string): string {
        return (this.integrationTypes as any[]).find((t: any) => t.type === type)?.abbr || type.slice(0,3).toUpperCase();
    }

    getIntIcon(type: string): string {
        return this.getIntAbbr(type);
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

    openEditIntegration(int: any) {
        this.editingIntId = int.id;
        this.intType = int.type;
        this.intName = int.name;
        this.intConfig = typeof int.config === 'object' ? { ...int.config } : {};
        this.testResult = '';
        this.showNewIntegration = true;
    }

    saveIntegration() {
        this.savingInt = true;
        const payload = {
            name: this.intName || this.selectedIntType?.name,
            type: this.intType,
            config: this.intConfig
        };

        const request$ = this.editingIntId
            ? this.api.updateIntegration(this.editingIntId, payload)
            : this.api.saveIntegration(payload);

        request$.subscribe({
            next: () => {
                this.savingInt = false;
                this.showNewIntegration = false;
                this.editingIntId = null;
                this.intConfig = {};
                this.intName = '';
                this.loadIntegrations();
            },
            error: () => {
                this.savingInt = false;
                this.cdr.detectChanges();
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