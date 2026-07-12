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
    Trash2, Bell, Mail, Globe, Shield, Activity, ShieldAlert,
    Ban, ShieldOff, WifiOff, Wifi, AlertCircle
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
    BanIcon = Ban;
    ShieldOffIcon = ShieldOff;
    WifiOffIcon = WifiOff;
    WifiIcon = Wifi;
    CheckCircleIcon = CheckCircle;
    AlertCircleIcon = AlertCircle;

    activeTab: 'cases' | 'playbooks' | 'integrations' | 'activity' | 'blocks' | 'isolations' = 'cases';
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

    // --- Active Blocks ---
    activeBlocks: any[] = [];
    loadingBlocks = false;
    showBlockModal = false;
    blockIp = '';
    blockPort: number | null = null;
    blockDuration = 24;
    blockEnforcement: 'rst' | 'firewall' | 'both' = 'both';
    blockReason = '';
    blockSaving = false;
    blockError = '';

    // --- Device Isolations ---
    isolations: any[] = [];
    loadingIsolations = false;
    showIsolateModal = false;
    isolateIp = '';
    isolateGateway = '192.168.1.1';
    isolateEnforcement: 'arp' | 'unifi' | 'cisco' | 'aruba' | 'snmp' | 'aws_sg' | 'azure_nsg' | 'gcp_vpc' = 'arp';
    isolateVlan = 999;
    isolateReason = '';
    isolateSaving = false;
    isolateError = '';

    // --- Isolation Progress Modal ---
    showIsolationProgress = false;
    isolationProgressTitle = '';
    isolationProgressTarget = '';
    isolationProgressSteps: { label: string; status: 'pending' | 'running' | 'done' | 'error' }[] = [];
    isolationProgressComplete = false;
    isolationProgressSuccess = false;
    isolationProgressError = '';

    isolationEnforcementTypes = [
        { value: 'arp',       label: 'ARP Spoofing (instant, agent-side)' },
        { value: 'unifi',     label: 'UniFi — Block Station (REST)' },
        { value: 'cisco',     label: 'Cisco IOS — VLAN quarantine (SNMP)' },
        { value: 'aruba',     label: 'Aruba CX — Access VLAN (REST)' },
        { value: 'snmp',      label: 'Generic Switch — VLAN quarantine (SNMP)' },
        { value: 'aws_sg',    label: 'AWS Security Group — revoke ingress' },
        { value: 'azure_nsg', label: 'Azure NSG — Deny inbound rule' },
        { value: 'gcp_vpc',   label: 'GCP VPC Firewall — Deny ingress rule' },
    ];

    firewallIntegrationTypes = [
        { type: 'pfsense',  name: 'pfSense',          fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }] },
        { type: 'fortinet', name: 'Fortinet FortiOS',  fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }] },
        { type: 'panos',    name: 'Palo Alto PAN-OS',  fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }] },
        { type: 'opnsense', name: 'OPNsense',           fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }, { key: 'api_secret', label: 'API Secret', placeholder: '...', type: 'password' }] },
        { type: 'rest',     name: 'Generic REST Webhook', fields: [{ key: 'url', label: 'Endpoint URL', placeholder: 'https://...' }] },
    ];

    integrationTypes = [
        // ── Notification channels ──────────────────────────────────────────
        {
            type: 'slack', name: 'Slack', abbr: 'SLK', group: 'notify',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/...', type: 'text' }]
        },
        {
            type: 'teams', name: 'MS Teams', abbr: 'TMS', group: 'notify',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://outlook.office.com/webhook/...', type: 'text' }]
        },
        {
            type: 'discord', name: 'Discord', abbr: 'DSC', group: 'notify',
            fields: [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://discord.com/api/webhooks/...', type: 'text' }]
        },
        {
            type: 'webhook', name: 'Webhook', abbr: 'WHK', group: 'notify',
            fields: [{ key: 'webhook_url', label: 'Endpoint URL', placeholder: 'https://your-endpoint.com/alert', type: 'text' }]
        },
        {
            type: 'smtp', name: 'Email', abbr: 'EML', group: 'notify',
            fields: [
                { key: 'smtp_host', label: 'SMTP Host', placeholder: 'smtp.gmail.com', type: 'text' },
                { key: 'smtp_port', label: 'SMTP Port', placeholder: '587', type: 'text' },
                { key: 'smtp_user', label: 'Username', placeholder: 'user@domain.com', type: 'text' },
                { key: 'smtp_pass', label: 'Password', placeholder: '••••••••', type: 'password' },
                { key: 'from_addr', label: 'From Address', placeholder: 'alerts@domain.com', type: 'text' },
                { key: 'to_addr', label: 'Recipient', placeholder: 'soc@domain.com', type: 'text' }
            ]
        },
        // ── Firewall / block enforcement ───────────────────────────────────
        {
            type: 'pfsense', name: 'pfSense', abbr: 'PFS', group: 'firewall',
            fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1', type: 'text' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }]
        },
        {
            type: 'fortinet', name: 'FortiGate', abbr: 'FGT', group: 'firewall',
            fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1', type: 'text' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }, { key: 'vdom', label: 'VDOM', placeholder: 'root', type: 'text' }]
        },
        {
            type: 'panos', name: 'PAN-OS', abbr: 'PAN', group: 'firewall',
            fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1', type: 'text' }, { key: 'api_key', label: 'API Key', placeholder: '...', type: 'password' }]
        },
        {
            type: 'opnsense', name: 'OPNsense', abbr: 'OPN', group: 'firewall',
            fields: [{ key: 'host', label: 'Host', placeholder: '192.168.1.1', type: 'text' }, { key: 'api_key', label: 'Key:Secret', placeholder: 'key:secret', type: 'password' }]
        },
        // ── Switch isolation ───────────────────────────────────────────────
        {
            type: 'unifi', name: 'UniFi', abbr: 'UFI', group: 'switch',
            fields: [
                { key: 'host', label: 'Controller URL', placeholder: 'https://192.168.1.1:8443', type: 'text' },
                { key: 'username', label: 'Username', placeholder: 'admin', type: 'text' },
                { key: 'password', label: 'Password', placeholder: '••••••••', type: 'password' },
                { key: 'site', label: 'Site', placeholder: 'default', type: 'text' }
            ]
        },
        {
            type: 'cisco', name: 'Cisco SNMP', abbr: 'CSC', group: 'switch',
            fields: [
                { key: 'host', label: 'Switch IP', placeholder: '192.168.1.2', type: 'text' },
                { key: 'community', label: 'Write Community', placeholder: 'private', type: 'password' },
                { key: 'port_ifindex', label: 'Port ifIndex', placeholder: '1', type: 'text' }
            ]
        },
        {
            type: 'aruba', name: 'Aruba CX', abbr: 'ARB', group: 'switch',
            fields: [
                { key: 'host', label: 'Switch URL', placeholder: 'https://192.168.1.3', type: 'text' },
                { key: 'username', label: 'Username', placeholder: 'admin', type: 'text' },
                { key: 'password', label: 'Password', placeholder: '••••••••', type: 'password' },
                { key: 'port', label: 'Port (e.g. 1/1/5)', placeholder: '1/1/5', type: 'text' }
            ]
        },
        {
            type: 'snmp', name: 'Generic SNMP', abbr: 'SNM', group: 'switch',
            fields: [
                { key: 'host', label: 'Switch IP', placeholder: '192.168.1.4', type: 'text' },
                { key: 'community', label: 'Write Community', placeholder: 'private', type: 'password' },
                { key: 'port_ifindex', label: 'Port ifIndex', placeholder: '1', type: 'text' }
            ]
        },
        // ── Cloud firewall ─────────────────────────────────────────────────
        {
            type: 'aws_sg', name: 'AWS SG', abbr: 'AWS', group: 'cloud',
            fields: [
                { key: 'sg_id', label: 'Security Group ID', placeholder: 'sg-0123456789abcdef', type: 'text' },
                { key: 'region', label: 'Region', placeholder: 'us-east-1', type: 'text' },
                { key: 'aws_access_key_id', label: 'Access Key ID', placeholder: 'AKIA...', type: 'text' },
                { key: 'aws_secret_access_key', label: 'Secret Access Key', placeholder: '...', type: 'password' }
            ]
        },
        {
            type: 'azure_nsg', name: 'Azure NSG', abbr: 'AZR', group: 'cloud',
            fields: [
                { key: 'resource_group', label: 'Resource Group', placeholder: 'my-rg', type: 'text' },
                { key: 'nsg_name', label: 'NSG Name', placeholder: 'my-nsg', type: 'text' },
                { key: 'subscription_id', label: 'Subscription ID (optional)', placeholder: '...', type: 'text' }
            ]
        },
        {
            type: 'gcp_vpc', name: 'GCP VPC', abbr: 'GCP', group: 'cloud',
            fields: [
                { key: 'project', label: 'Project ID', placeholder: 'my-project', type: 'text' },
                { key: 'network', label: 'Network', placeholder: 'default', type: 'text' }
            ]
        },
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
    switchTab(tab: 'cases' | 'playbooks' | 'integrations' | 'activity' | 'blocks' | 'isolations') {
        this.activeTab = tab;
        if (tab === 'cases') this.loadCases();
        if (tab === 'playbooks') this.loadPlaybooks();
        if (tab === 'integrations') this.loadIntegrations();
        if (tab === 'activity') this.loadRuns();
        if (tab === 'blocks') this.loadBlocks();
        if (tab === 'isolations') this.loadIsolations();
    }

    // --- Blocks Logic ---
    loadBlocks() {
        this.loadingBlocks = true;
        this.api.listActiveBlocks().subscribe({
            next: (res: any) => {
                this.activeBlocks = res.data || [];
                this.loadingBlocks = false;
                this.cdr.detectChanges();
            },
            error: () => { this.loadingBlocks = false; this.cdr.detectChanges(); }
        });
    }

    revokeBlock(b: any) {
        if (!confirm(`Revoke block on ${b.src_ip}?`)) return;
        this.api.revokeBlock(b.id, b.sensor_id || undefined).subscribe({
            next: () => this.loadBlocks(),
            error: () => alert('Failed to revoke block')
        });
    }

    openBlockModal() {
        this.blockIp = '';
        this.blockPort = null;
        this.blockDuration = 24;
        this.blockEnforcement = 'both';
        this.blockReason = '';
        this.blockError = '';
        this.showBlockModal = true;
    }

    submitManualBlock() {
        if (!this.blockIp.trim()) { this.blockError = 'IP address is required'; return; }
        this.blockSaving = true;
        this.blockError = '';
        this.api.manualBlock({
            src_ip:         this.blockIp.trim(),
            src_port:       this.blockPort ?? undefined,
            duration_hours: this.blockDuration,
            enforcement:    this.blockEnforcement,
            reason:         this.blockReason || undefined,
        }).subscribe({
            next: (res: any) => {
                this.blockSaving = false;
                if (res.status === 'success') {
                    this.showBlockModal = false;
                    this.loadBlocks();
                } else {
                    this.blockError = res.message || 'Block failed';
                    this.cdr.detectChanges();
                }
            },
            error: (err: any) => {
                this.blockSaving = false;
                this.blockError = err.error?.message || 'Request failed';
                this.cdr.detectChanges();
            }
        });
    }

    // --- Isolations Logic ---
    loadIsolations() {
        this.loadingIsolations = true;
        this.api.listIsolations().subscribe({
            next: (res: any) => {
                this.isolations = res.data || [];
                this.loadingIsolations = false;
                this.cdr.detectChanges();
            },
            error: () => { this.loadingIsolations = false; this.cdr.detectChanges(); }
        });
    }

    openIsolateModal() {
        this.isolateIp = '';
        this.isolateGateway = '192.168.1.1';
        this.isolateEnforcement = 'arp';
        this.isolateVlan = 999;
        this.isolateReason = '';
        this.isolateError = '';
        this.showIsolateModal = true;
    }

    private startIsolationProgress(title: string, target: string, steps: string[]) {
        this.isolationProgressTitle = title;
        this.isolationProgressTarget = target;
        this.isolationProgressSteps = steps.map(label => ({ label, status: 'pending' as const }));
        this.isolationProgressComplete = false;
        this.isolationProgressSuccess = false;
        this.isolationProgressError = '';
        this.showIsolationProgress = true;
        this.cdr.detectChanges();
    }

    private async runIsolationSteps(apiCall: Promise<any>, stepDelays: number[]) {
        // Animate through all but last step while API call is in-flight
        let stepIndex = 0;
        const advance = (idx: number) => {
            if (idx > 0) this.isolationProgressSteps[idx - 1].status = 'done';
            this.isolationProgressSteps[idx].status = 'running';
            this.cdr.detectChanges();
        };
        advance(stepIndex);
        const timers: ReturnType<typeof setTimeout>[] = [];
        for (let i = 1; i < this.isolationProgressSteps.length - 1; i++) {
            const delay = stepDelays[i - 1] ?? (i * 900);
            timers.push(setTimeout(() => { advance(i); stepIndex = i; this.cdr.detectChanges(); }, delay));
        }
        try {
            const res = await apiCall;
            timers.forEach(t => clearTimeout(t));
            // Complete all steps
            this.isolationProgressSteps.forEach(s => s.status = 'done');
            this.isolationProgressComplete = true;
            this.isolationProgressSuccess = true;
            this.isolationProgressError = res?.message && res.status !== 'success' ? res.message : '';
            if (res?.status !== 'success' && res?.message) {
                this.isolationProgressSteps[this.isolationProgressSteps.length - 1].status = 'error';
                this.isolationProgressSuccess = false;
                this.isolationProgressError = res.message;
            }
        } catch (err: any) {
            timers.forEach(t => clearTimeout(t));
            const failIdx = this.isolationProgressSteps.findIndex(s => s.status === 'running');
            if (failIdx >= 0) this.isolationProgressSteps[failIdx].status = 'error';
            this.isolationProgressComplete = true;
            this.isolationProgressSuccess = false;
            this.isolationProgressError = err?.error?.message || err?.message || 'Request failed';
        }
        this.cdr.detectChanges();
        this.loadIsolations();
    }

    submitIsolation() {
        if (!this.isolateIp.trim()) { this.isolateError = 'IP address is required'; return; }
        const ip = this.isolateIp.trim();
        const enforcement = this.isolateEnforcement;
        this.showIsolateModal = false;

        const isArp = enforcement === 'arp';
        const steps = isArp
            ? ['Connecting to sensor agent', 'Starting ARP poisoning', 'Applying iptables firewall rules', 'Confirming device isolation']
            : ['Connecting to sensor agent', `Sending ${enforcement.toUpperCase()} quarantine command`, 'Waiting for enforcement confirmation', 'Confirming device isolation'];

        this.startIsolationProgress('Isolating Device', ip, steps);

        const apiPromise = new Promise<any>((resolve, reject) => {
            this.api.isolateDevice({
                target_ip:       ip,
                gateway_ip:      this.isolateGateway || undefined,
                enforcement,
                quarantine_vlan: this.isolateVlan,
                reason:          this.isolateReason || undefined,
            }).subscribe({ next: resolve, error: reject });
        });
        this.runIsolationSteps(apiPromise, [800, 1800, 2800]);
    }

    restoreIsolation(iso: any) {
        const enforcement = iso.enforcement || 'arp';
        const isArp = enforcement === 'arp';
        const steps = isArp
            ? ['Connecting to sensor agent', 'Stopping ARP poisoning', 'Removing iptables firewall rules', 'Network access restored']
            : ['Connecting to sensor agent', `Reverting ${enforcement.toUpperCase()} quarantine`, 'Waiting for enforcement rollback', 'Network access restored'];

        this.startIsolationProgress('Restoring Device', iso.target_ip, steps);

        const apiPromise = new Promise<any>((resolve, reject) => {
            this.api.unisolateDevice(iso.id).subscribe({ next: resolve, error: reject });
        });
        this.runIsolationSteps(apiPromise, [800, 1800, 2800]);
    }

    closeIsolationProgress() {
        this.showIsolationProgress = false;
    }

    isolationMethodLabel(enforcement: string): string {
        return this.isolationEnforcementTypes.find(t => t.value === enforcement)?.label.split(' — ')[0] || enforcement;
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
    integrationsByGroup(group: string): any[] {
        return this.integrationTypes.filter((t: any) => t.group === group);
    }

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