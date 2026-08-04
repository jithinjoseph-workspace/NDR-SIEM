import { Component, OnInit, ChangeDetectorRef, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { Api } from '../../../services/api/api';
import { ArkimeService } from '../../../services/arkime/arkime';
import {
    LucideAngularModule,
    Zap, Play, Pause, Settings,
    CheckCircle, XCircle, Link,
    RefreshCw, ExternalLink, Plus,
    Trash2, Bell, Mail, Globe, Shield, Activity, ShieldAlert,
    Ban, ShieldOff, WifiOff, Wifi, AlertCircle
} from 'lucide-angular';
import { AuthService } from '../../../services/auth/auth';


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
            type: 'pagerduty', name: 'PagerDuty', abbr: 'PDY', group: 'notify',
            fields: [{ key: 'routing_key', label: 'Routing Key', placeholder: 'abc123...', type: 'password' }]
        },
        {
            type: 'telegram', name: 'Telegram', abbr: 'TGM', group: 'notify',
            fields: [
                { key: 'bot_token', label: 'Bot Token', placeholder: '123456:ABC-DEF...', type: 'password' },
                { key: 'chat_id',   label: 'Chat ID',   placeholder: '-1001234567890',   type: 'text' }
            ]
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
    dismissedSessionIds = new Set<string>();
    collectingPcap = false;
    collectPcapDone = false;
    showEvidenceOverlay  = false;
    evidenceOverlaySrc: SafeResourceUrl = '';
    selectedSession: any = null;

    // ── Case Close / Resolve form ─────────────────────────────────────
    showCloseForm    = false;
    pendingStatus    = '';
    closeNotes       = '';
    addToIntel       = true;
    intelGroup       = '';
    incidentReport: any = null;

    /** Sensor IDs this user is scoped to (from JWT). */
    sensorIds: string[] = [];

    /** Display name of the currently logged-in analyst. */
    currentUsername = '';

    constructor(private api: Api, private arkime: ArkimeService, private cdr: ChangeDetectorRef, private auth: AuthService, private router: Router, private sanitizer: DomSanitizer) {}

    viewEvidence(cid: string) {
        const c = this.selectedCase;
        let url = `/analyst/evidence?cid=${encodeURIComponent(cid)}`;
        if (c?.src_ip) url += `&src_ip=${encodeURIComponent(c.src_ip)}`;
        if (c?.dst_ip) url += `&dst_ip=${encodeURIComponent(c.dst_ip)}`;
        this.evidenceOverlaySrc  = this.sanitizer.bypassSecurityTrustResourceUrl(url);
        this.showEvidenceOverlay = true;
        this.cdr.detectChanges();
    }

    closeEvidenceOverlay() {
        this.showEvidenceOverlay = false;
        this.evidenceOverlaySrc  = '';
        this.cdr.detectChanges();
    }

    dismissSession(sessionId: string) {
        this.dismissedSessionIds = new Set([...this.dismissedSessionIds, sessionId]);
        this.cdr.detectChanges();
    }

    visibleSessions(): any[] {
        return (this.liveEvidence?.pcap_sessions || []).filter((s: any) => !this.dismissedSessionIds.has(s.id));
    }

    sessionNote = '';

    // ── PCAP file viewer ─────────────────────────────────────────────────────
    pcapViewSession: any = null;
    pcapPackets: any[]  = [];
    pcapLoading         = false;
    pcapError           = '';
    pcapNote            = '';
    showPcapAnalysis    = false;
    pcapAnalysis: any   = null;
    paActiveTab         = 'overview';
    @ViewChild('paChartCanvas') paChartCanvas?: ElementRef<HTMLCanvasElement>;
    expandedPktIdx      = new Set<number>();

    analyzeSession(session: any) {
        this.selectedSession = session;
        this.sessionNote = '';
        this.cdr.detectChanges();
    }

    closeSessionDetail() {
        this.selectedSession = null;
        this.sessionNote = '';
        this.cdr.detectChanges();
    }

    addSessionNote(session: any) {
        if (!this.sessionNote.trim() || !this.selectedCase) return;
        const flow = `${session.src_ip}:${session.src_port} → ${session.dst_ip}:${session.dst_port}`;
        const proto = (session.proto || 'TCP').toUpperCase();
        const comment = `[SESSION NOTE — ${flow} ${proto}] ${this.sessionNote.trim()}`;
        this.api.addSoarCaseComment(this.selectedCase.id, comment).subscribe((res: any) => {
            if (res.status === 'success') {
                this.sessionNote = '';
                this.openCase(this.selectedCase);
                this.cdr.detectChanges();
            }
        });
    }

    openPcapViewer(session: any) {
        this.pcapViewSession = session;
        this.pcapPackets = [];
        this.pcapError   = '';
        this.pcapNote    = '';
        this.expandedPktIdx = new Set();
        this.pcapLoading = true;
        this.cdr.detectChanges();
        const id   = session.id || session.session_id;
        const node = session.sensor_host || '';
        this.arkime.fetchPcapRaw(id, node, session).subscribe({
            next: (buf: ArrayBuffer) => {
                this.pcapLoading = false;
                if (buf.byteLength === 0) {
                    this.pcapError = 'PCAP file is empty. The capture may not be stored yet.';
                    this.cdr.detectChanges();
                    return;
                }
                // Detect if response is JSON/text error instead of binary PCAP
                const firstByte = new Uint8Array(buf)[0];
                if (firstByte === 0x7b || firstByte === 0x3c || firstByte === 0x50) { // { or < or P (JSON/HTML)
                    try {
                        const text = new TextDecoder().decode(buf.slice(0, 512));
                        const parsed = JSON.parse(text);
                        this.pcapError = parsed.message || parsed.error || 'PCAP not available from server.';
                    } catch {
                        // HTML error page from Arkime — session has no stored capture
                        this.pcapError = 'No packet capture stored for this session. Use ↓ Download to try fetching from Arkime directly.';
                    }
                    this.cdr.detectChanges();
                    return;
                }
                // Detect pcapng format (magic 0x0a0d0d0a) — not yet parseable inline
                const v = new DataView(buf);
                const magic = v.getUint32(0, false);
                if (magic === 0x0a0d0d0a) {
                    this.pcapError = 'PCAP-NG format detected. Use ↓ Download to open in Wireshark.';
                    this.cdr.detectChanges();
                    return;
                }
                this.pcapPackets = this.parsePcap(buf);
                if (!this.pcapPackets.length) {
                    this.pcapError = 'Could not parse PCAP — unrecognised format. Use ↓ Download to open in Wireshark.';
                }
                this.cdr.detectChanges();
            },
            error: (e: any) => {
                this.pcapLoading = false;
                const raw = e?.error ? (() => { try { return new TextDecoder().decode(e.error); } catch { return ''; } })() : '';
                if (e?.status === 404 || raw.toLowerCase().includes('not found') || raw.toLowerCase().includes('not available')) {
                    this.pcapError = 'No packet capture stored for this session. Use ↓ Download to try fetching from Arkime directly.';
                } else if (e?.status === 502) {
                    this.pcapError = 'Arkime is not running on this sensor — PCAP is unavailable. Start Arkime and try again.';
                } else {
                    this.pcapError = raw || e?.message || 'PCAP not available — no local capture and Arkime is not configured.';
                }
                this.cdr.detectChanges();
            }
        });
    }

    closePcapViewer() {
        this.pcapViewSession = null;
        this.pcapPackets = [];
        this.pcapNote = '';
        this.cdr.detectChanges();
    }

    togglePktExpand(idx: number) {
        if (this.expandedPktIdx.has(idx)) {
            this.expandedPktIdx.delete(idx);
        } else {
            this.expandedPktIdx.add(idx);
        }
        this.expandedPktIdx = new Set(this.expandedPktIdx);
        this.cdr.detectChanges();
    }

    addPcapNote() {
        if (!this.pcapNote.trim() || !this.selectedCase) return;
        const s = this.pcapViewSession;
        const flow = s ? `${s.src_ip}:${s.src_port} → ${s.dst_ip}:${s.dst_port}` : '';
        const comment = `[PCAP ANALYSIS${flow ? ' — ' + flow : ''}] ${this.pcapNote.trim()}`;
        this.api.addSoarCaseComment(this.selectedCase.id, comment).subscribe((res: any) => {
            if (res.status === 'success') {
                this.pcapNote = '';
                this.openCase(this.selectedCase);
                this.cdr.detectChanges();
            }
        });
    }

    // ── Binary PCAP parser ────────────────────────────────────────────────────
    private parsePcap(buf: ArrayBuffer): any[] {
        if (buf.byteLength < 24) return [];
        const v    = new DataView(buf);
        // Read magic as big-endian to detect file byte order:
        // LE pcap (Linux/x86): bytes d4 c3 b2 a1 → big-endian read = 0xd4c3b2a1 → isLE = true
        // BE pcap (SPARC etc): bytes a1 b2 c3 d4 → big-endian read = 0xa1b2c3d4 → isLE = false
        const magicBE = v.getUint32(0, false);
        const isLE = (magicBE === 0xd4c3b2a1 || magicBE === 0x4d3cb2a1); // LE variants (standard + nanosec)
        const linkType = v.getUint32(20, isLE);
        let off = 24;
        const pkts: any[] = [];
        let idx = 1;
        let t0Sec = 0, t0Usec = 0;
        while (off + 16 <= buf.byteLength) {
            const tsSec  = v.getUint32(off,     isLE);
            const tsUsec = v.getUint32(off + 4, isLE);
            const inclLen = v.getUint32(off + 8,  isLE);
            const origLen = v.getUint32(off + 12, isLE);
            off += 16;
            if (inclLen > buf.byteLength - off || inclLen > 65536) break;
            if (idx === 1) { t0Sec = tsSec; t0Usec = tsUsec; }
            const relUs = (tsSec - t0Sec) * 1_000_000 + (tsUsec - t0Usec);
            const relMs = relUs / 1000;
            const pktData = new Uint8Array(buf, off, inclLen);
            const pkt: any = { idx, ts: relMs, len: inclLen, orig_len: origLen };
            if (linkType === 1)   this.parseEthernet(pktData, pkt);
            else if (linkType === 101) this.parseIPv4(pktData, 0, pkt);
            pkt.hexLines = this.toHexLines(pktData);
            pkts.push(pkt);
            off += inclLen;
            idx++;
        }
        return pkts;
    }

    private parseEthernet(data: Uint8Array, pkt: any) {
        if (data.length < 14) return;
        pkt.dst_mac = Array.from(data.slice(0, 6)).map((b: number) => b.toString(16).padStart(2,'0')).join(':');
        pkt.src_mac = Array.from(data.slice(6, 12)).map((b: number) => b.toString(16).padStart(2,'0')).join(':');
        const et = (data[12] << 8) | data[13];
        if (et === 0x0800) this.parseIPv4(data, 14, pkt);
        else if (et === 0x0806) { pkt.proto = 'ARP'; pkt.info = 'ARP request/reply'; }
        else if (et === 0x86dd) { pkt.proto = 'IPv6'; pkt.info = 'IPv6'; }
        else { pkt.proto = `0x${et.toString(16)}`; pkt.info = `EtherType ${pkt.proto}`; }
    }

    private parseIPv4(data: Uint8Array, off: number, pkt: any) {
        if (data.length < off + 20) return;
        const ihl = (data[off] & 0x0f) * 4;
        const proto = data[off + 9];
        pkt.src_ip = `${data[off+12]}.${data[off+13]}.${data[off+14]}.${data[off+15]}`;
        pkt.dst_ip = `${data[off+16]}.${data[off+17]}.${data[off+18]}.${data[off+19]}`;
        pkt.ttl    = data[off + 8];
        pkt.ipId   = (data[off+4] << 8) | data[off+5];
        const ipPayoff = off + ihl;
        if      (proto === 6)  this.parseTCP(data, ipPayoff, pkt);
        else if (proto === 17) this.parseUDP(data, ipPayoff, pkt);
        else if (proto === 1)  this.parseICMP(data, ipPayoff, pkt);
        else { pkt.proto = `IP/${proto}`; pkt.info = `${pkt.src_ip} → ${pkt.dst_ip}`; }
    }

    private parseICMP(data: Uint8Array, off: number, pkt: any) {
        pkt.proto = 'ICMP';
        if (data.length < off + 4) { pkt.info = 'ICMP'; return; }
        const type = data[off], code = data[off+1];
        const ICMP_TYPES: Record<number, string> = {
            0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench',
            5: 'Redirect', 8: 'Echo Request', 9: 'Router Advertisement',
            10: 'Router Solicitation', 11: 'Time Exceeded', 12: 'Parameter Problem',
            13: 'Timestamp', 14: 'Timestamp Reply', 30: 'Traceroute',
        };
        const UNREACH_CODES: Record<number, string> = {
            0:'Net Unreachable', 1:'Host Unreachable', 2:'Protocol Unreachable',
            3:'Port Unreachable', 4:'Fragmentation Needed', 9:'Net Admin Prohibited',
            10:'Host Admin Prohibited', 13:'Communication Prohibited',
        };
        const typeName = ICMP_TYPES[type] || `Type ${type}`;
        const codeName = type === 3 ? (UNREACH_CODES[code] || `code ${code}`) :
                         type === 11 ? (code === 0 ? 'TTL Exceeded in Transit' : 'Fragment Reassembly Exceeded') :
                         type === 5  ? (['Net','Host','TOS+Net','TOS+Host'][code] || `code ${code}`) + ' Redirect' : '';
        pkt.info = codeName ? `${typeName} (${codeName})` : typeName;
        pkt.icmpDecoded = [
            { k: 'Type', v: `${type} — ${typeName}` },
            { k: 'Code', v: codeName || String(code) },
        ];
        // Echo request/reply: show id + seq
        if ((type === 8 || type === 0) && data.length >= off + 8) {
            const id  = (data[off+4] << 8) | data[off+5];
            const seq = (data[off+6] << 8) | data[off+7];
            pkt.icmpDecoded.push({ k: 'Identifier', v: String(id) });
            pkt.icmpDecoded.push({ k: 'Sequence',   v: String(seq) });
            pkt.info = `${typeName}  id=${id}  seq=${seq}`;
        }
    }

    private parseTCP(data: Uint8Array, off: number, pkt: any) {
        if (data.length < off + 20) return;
        pkt.proto = 'TCP';
        pkt.src_port = (data[off] << 8) | data[off+1];
        pkt.dst_port = (data[off+2] << 8) | data[off+3];
        const fl = data[off+13];
        const fs = [fl&0x02?'SYN':'', fl&0x10?'ACK':'', fl&0x01?'FIN':'', fl&0x04?'RST':'', fl&0x08?'PSH':''].filter(Boolean).join('+');
        pkt.flags = fs;
        const dOff = ((data[off+12] >> 4) * 4);
        const pl = data.slice(off + dOff);
        if (pl.length > 0) {
            const txt = new TextDecoder('utf-8', { fatal: false }).decode(pl.slice(0, 4096));
            if (/^(GET |POST |PUT |DELETE |HEAD |PATCH |OPTIONS |HTTP\/)/.test(txt)) {
                pkt.proto = 'HTTP';
                const lines = txt.split('\r\n');
                pkt.info = lines[0].slice(0, 100);
                // Parse all headers into key→value pairs
                pkt.httpFirstLine = lines[0];
                pkt.httpHeaders = [];
                let bodyStart = -1;
                for (let i = 1; i < lines.length; i++) {
                    if (lines[i] === '') { bodyStart = i + 1; break; }
                    const colon = lines[i].indexOf(':');
                    if (colon > 0) {
                        pkt.httpHeaders.push({ k: lines[i].slice(0, colon).trim(), v: lines[i].slice(colon + 1).trim() });
                    }
                }
                // Detect content-encoding for body display
                const ceHeader = pkt.httpHeaders.find((h: any) => h.k.toLowerCase() === 'content-encoding');
                const encoding = ceHeader?.v?.toLowerCase() || '';
                const clHeader = pkt.httpHeaders.find((h: any) => h.k.toLowerCase() === 'content-length');
                const bodyLen  = clHeader ? parseInt(clHeader.v, 10) : 0;
                if (bodyStart > 0) {
                    if (encoding === 'gzip' || encoding === 'deflate' || encoding === 'br') {
                        pkt.httpBodyNote = `Body is ${encoding}-compressed (${bodyLen ? bodyLen + ' bytes' : 'binary'}) — download PCAP and open in Wireshark to view decoded content.`;
                    } else if (bodyStart < lines.length) {
                        const body = lines.slice(bodyStart).join('\r\n').slice(0, 1024);
                        if (body.trim()) pkt.httpBody = body;
                    }
                }
            } else if (pl[0] === 0x16 && pl[1] === 0x03) {
                pkt.proto = 'TLS';
                const tlsTypes: Record<number,string> = {1:'ClientHello',2:'ServerHello',11:'Certificate',12:'ServerKeyExchange',14:'ServerHelloDone',16:'ClientKeyExchange',20:'ChangeCipherSpec'};
                const hsType = pl.length > 5 ? pl[5] : 0;
                const hsName = tlsTypes[hsType] || 'Handshake';
                pkt.info = `TLS ${hsName}`;
                pkt.tlsDecoded = [
                    { k: 'Record Type', v: 'Handshake (22)' },
                    { k: 'Version',     v: pl.length > 2 ? `TLS 1.${pl[2] === 1 ? '0' : pl[2] === 2 ? '1' : pl[2] === 3 ? '2' : '?'}` : '?' },
                    { k: 'Handshake',   v: hsName },
                ];
                // Extract SNI from ClientHello (type=1)
                if (hsType === 1 && pl.length > 43) {
                    try {
                        let i = 43;
                        const sessLen = pl[i++];
                        i += sessLen;
                        const ciphLen = (pl[i] << 8) | pl[i+1]; i += 2 + ciphLen;
                        const compLen = pl[i++]; i += compLen;
                        if (i + 2 < pl.length) {
                            const extTotal = (pl[i] << 8) | pl[i+1]; i += 2;
                            const extEnd = i + extTotal;
                            while (i + 4 < extEnd) {
                                const extType = (pl[i] << 8) | pl[i+1]; i += 2;
                                const extLen  = (pl[i] << 8) | pl[i+1]; i += 2;
                                if (extType === 0 && i + 5 < pl.length) { // SNI
                                    const nameLen = (pl[i+3] << 8) | pl[i+4];
                                    const sni = String.fromCharCode(...Array.from(pl.slice(i+5, i+5+nameLen)));
                                    pkt.tlsDecoded.push({ k: 'SNI (server name)', v: sni });
                                    pkt.info = `TLS ClientHello → ${sni}`;
                                    break;
                                }
                                i += extLen;
                            }
                        }
                    } catch (_) {}
                }
            }
        }
        if (!pkt.info) pkt.info = `${pkt.src_ip}:${pkt.src_port} → ${pkt.dst_ip}:${pkt.dst_port} [${fs || 'ACK'}]`;
    }

    private parseUDP(data: Uint8Array, off: number, pkt: any) {
        if (data.length < off + 8) return;
        pkt.proto = 'UDP';
        pkt.src_port = (data[off] << 8) | data[off+1];
        pkt.dst_port = (data[off+2] << 8) | data[off+3];
        const pl = data.slice(off + 8);
        if (pkt.src_port === 53 || pkt.dst_port === 53) {
            pkt.proto = 'DNS';
            this.parseDNS(pl, pkt);
        } else if (pkt.src_port === 67 || pkt.dst_port === 67) {
            pkt.proto = 'DHCP'; pkt.info = 'DHCP';
        } else {
            pkt.info = `${pkt.src_ip}:${pkt.src_port} → ${pkt.dst_ip}:${pkt.dst_port}`;
        }
    }

    private parseDNS(data: Uint8Array, pkt: any) {
        if (data.length < 12) { pkt.info = 'DNS'; return; }
        const flags   = (data[2] << 8) | data[3];
        const isResp  = !!(flags & 0x8000);
        const qdCount = (data[4] << 8) | data[5];
        const anCount = (data[6] << 8) | data[7];
        const rcode   = flags & 0x000f;
        const rcodes: Record<number,string> = {0:'No Error',1:'Format Error',2:'Server Failure',3:'NXDOMAIN',5:'Refused'};
        // Read first question name
        const readName = (off: number): [string, number] => {
            const parts: string[] = [];
            let i = off, safety = 0;
            while (i < data.length && data[i] !== 0 && safety++ < 64) {
                if ((data[i] & 0xc0) === 0xc0) { // pointer
                    const ptr = ((data[i] & 0x3f) << 8) | data[i+1];
                    parts.push(readName(ptr)[0]); i += 2; break;
                }
                const len = data[i++];
                parts.push(String.fromCharCode(...Array.from(data.slice(i, i+len)))); i += len;
            }
            return [parts.join('.'), i + 1];
        };
        const QTYPES: Record<number,string> = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',255:'ANY'};
        let qname = '', qtype = '';
        if (qdCount > 0 && data.length > 12) {
            const [name, end] = readName(12);
            qname = name;
            if (end + 1 < data.length) qtype = QTYPES[(data[end] << 8) | data[end+1]] || String((data[end] << 8) | data[end+1]);
        }
        if (isResp) {
            const status = rcodes[rcode] || `rcode=${rcode}`;
            pkt.info = `DNS Response: ${qname} [${status}]${anCount ? ` (${anCount} answer${anCount>1?'s':''})` : ''}`;
        } else {
            pkt.info = `DNS Query: ${qname}${qtype ? ' (' + qtype + ')' : ''}`;
        }
        pkt.dnsDecoded = [
            { k: 'Direction',  v: isResp ? 'Response' : 'Query' },
            { k: 'Name',       v: qname || '—' },
            { k: 'Type',       v: qtype || '—' },
            { k: 'Questions',  v: String(qdCount) },
            { k: 'Answers',    v: String(anCount) },
            ...(isResp ? [{ k: 'Status', v: rcodes[rcode] || `rcode=${rcode}` }] : []),
        ];
    }

    private toHexLines(data: Uint8Array): string[] {
        const lines: string[] = [];
        for (let i = 0; i < Math.min(data.length, 512); i += 16) {
            const chunk = Array.from(data.slice(i, i + 16));
            const hex   = chunk.map((b: number) => b.toString(16).padStart(2,'0')).join(' ').padEnd(47, ' ');
            const ascii = chunk.map((b: number) => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
            lines.push(`${i.toString(16).padStart(4,'0')}  ${hex}  ${ascii}`);
        }
        if (data.length > 512) lines.push(`      ... ${data.length - 512} more bytes`);
        return lines;
    }

    protoColor(proto: string): string {
        switch ((proto || '').toUpperCase()) {
            case 'HTTP':  return 'text-green-400';
            case 'TLS':   return 'text-blue-400';
            case 'DNS':   return 'text-yellow-400';
            case 'TCP':   return 'text-sky-400';
            case 'UDP':   return 'text-purple-400';
            case 'ICMP':  return 'text-orange-400';
            case 'ARP':   return 'text-pink-400';
            default:      return 'text-on-surface-variant';
        }
    }

    isKeyHeader(key: string): boolean {
        const important = ['host', 'content-type', 'user-agent', 'authorization', 'cookie', 'set-cookie', 'location', 'server', 'x-forwarded-for'];
        return important.includes((key || '').toLowerCase());
    }

    openPcapAnalysis() {
        const pkts = this.pcapPackets;
        const totalBytes = pkts.reduce((s: number, p: any) => s + (p.len || 0), 0);

        // Protocol counts
        const protocols: Record<string, number> = {};
        for (const p of pkts) {
            const proto = p.proto || 'Other';
            protocols[proto] = (protocols[proto] || 0) + 1;
        }

        // Unique bidirectional connections
        const connMap = new Map<string, any>();
        for (const p of pkts) {
            if (!p.src_ip || !p.dst_ip) continue;
            // Normalise so A→B and B→A are the same flow
            const [a, b] = [`${p.src_ip}:${p.src_port||''}`, `${p.dst_ip}:${p.dst_port||''}`];
            const key = a < b ? `${a}|${b}` : `${b}|${a}`;
            if (!connMap.has(key)) connMap.set(key, { src: `${p.src_ip}${p.src_port?':'+p.src_port:''}`, dst: `${p.dst_ip}${p.dst_port?':'+p.dst_port:''}`, proto: p.proto, pkts: 0, bytes: 0 });
            const c = connMap.get(key);
            c.pkts++;
            c.bytes += p.len || 0;
        }
        const connections = [...connMap.values()].sort((a: any, b: any) => b.bytes - a.bytes);

        // HTTP requests/responses
        const http: any[] = [];
        for (const p of pkts) {
            if (!p.httpFirstLine) continue;
            const host = p.httpHeaders?.find((h: any) => h.k.toLowerCase() === 'host')?.v || '';
            const ct   = p.httpHeaders?.find((h: any) => h.k.toLowerCase() === 'content-type')?.v || '';
            const ua   = p.httpHeaders?.find((h: any) => h.k.toLowerCase() === 'user-agent')?.v || '';
            http.push({ line: p.httpFirstLine, host, ct, ua, src: p.src_ip, dst: p.dst_ip });
        }

        // DNS queries/responses (deduplicated by name)
        const dnsMap = new Map<string, any>();
        for (const p of pkts) {
            if (!p.dnsDecoded?.length) continue;
            const name = p.dnsDecoded.find((h: any) => h.k === 'Name')?.v || '—';
            const type = p.dnsDecoded.find((h: any) => h.k === 'Type')?.v || '';
            const dir  = p.dnsDecoded.find((h: any) => h.k === 'Direction')?.v || '';
            const stat = p.dnsDecoded.find((h: any) => h.k === 'Status')?.v || '';
            const key  = `${name}|${type}`;
            if (!dnsMap.has(key)) dnsMap.set(key, { name, type, status: stat, hasResp: dir === 'Response' });
            else if (dir === 'Response') { dnsMap.get(key).status = stat; dnsMap.get(key).hasResp = true; }
        }
        const dns = [...dnsMap.values()];

        // TLS connections (deduplicated by SNI)
        const tlsMap = new Map<string, any>();
        for (const p of pkts) {
            if (!p.tlsDecoded?.length) continue;
            const sni = p.tlsDecoded.find((h: any) => h.k === 'SNI (server name)')?.v || '';
            const hs  = p.tlsDecoded.find((h: any) => h.k === 'Handshake')?.v || '';
            const ver = p.tlsDecoded.find((h: any) => h.k === 'Version')?.v || '';
            const key = sni || `${p.src_ip}→${p.dst_ip}`;
            if (!tlsMap.has(key)) tlsMap.set(key, { sni: sni || '(no SNI)', hs, ver, dst: p.dst_ip, count: 0 });
            tlsMap.get(key).count++;
        }
        const tls = [...tlsMap.values()];

        // ICMP summary
        const icmp: any[] = [];
        for (const p of pkts) {
            if (!p.icmpDecoded?.length) continue;
            const typeV = p.icmpDecoded.find((h: any) => h.k === 'Type')?.v || '';
            const desc  = p.icmpDecoded.find((h: any) => h.k === 'Description')?.v || p.info || '';
            icmp.push({ desc, type: typeV, src: p.src_ip, dst: p.dst_ip });
        }

        this.pcapAnalysis = { totalPackets: pkts.length, totalBytes, protocols, connections, http, dns, tls, icmp };
        this.paActiveTab = 'overview';
        this.showPcapAnalysis = true;
        setTimeout(() => this.drawPcapChart(), 60);
    }

    setpaTab(tab: string) {
        this.paActiveTab = tab;
        if (tab === 'overview') setTimeout(() => this.drawPcapChart(), 60);
    }

    drawPcapChart() {
        const canvas = document.getElementById('pa-chart-canvas') as HTMLCanvasElement | null;
        if (!canvas || !this.pcapAnalysis) return;
        const pkts = this.pcapPackets;
        if (!pkts.length) return;

        const dpr = window.devicePixelRatio || 1;
        const W = canvas.offsetWidth;
        const H = canvas.offsetHeight;
        canvas.width  = W * dpr;
        canvas.height = H * dpr;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.scale(dpr, dpr);

        const maxTs = pkts[pkts.length - 1]?.ts || 1;
        const BUCKETS = 60;
        const protos  = ['HTTP', 'TLS', 'DNS', 'ICMP', 'UDP', 'TCP', 'ARP', 'Other'];
        const colors: Record<string, string> = {
            HTTP:  '#86efac', TLS: '#93c5fd', DNS: '#fcd34d',
            ICMP:  '#fdba74', UDP: '#c4b5fd', TCP: '#38bdf8',
            ARP:   '#f9a8d4', Other: 'rgba(255,255,255,0.18)'
        };

        // Build stacked data: buckets × proto → bytes
        const data: Record<string, number[]> = {};
        for (const pr of protos) data[pr] = new Array(BUCKETS).fill(0);
        for (const p of pkts) {
            const bi = Math.min(Math.floor((p.ts / maxTs) * BUCKETS), BUCKETS - 1);
            const pr = protos.includes(p.proto) ? p.proto : 'Other';
            data[pr][bi] += p.len || 0;
        }

        // Max stacked value
        let maxVal = 1;
        for (let i = 0; i < BUCKETS; i++) {
            const sum = protos.reduce((s, pr) => s + data[pr][i], 0);
            if (sum > maxVal) maxVal = sum;
        }

        const pad = { top: 16, right: 8, bottom: 24, left: 48 };
        const cW = W - pad.left - pad.right;
        const cH = H - pad.top - pad.bottom;
        const bw = cW / BUCKETS;

        ctx.clearRect(0, 0, W, H);

        // Grid lines
        ctx.strokeStyle = 'rgba(255,255,255,0.06)';
        ctx.lineWidth = 1;
        for (let g = 0; g <= 4; g++) {
            const y = pad.top + cH - (g / 4) * cH;
            ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cW, y); ctx.stroke();
        }

        // Draw stacked area (each proto fills on top of previous)
        const stackBottom = new Array(BUCKETS).fill(0);
        for (const pr of [...protos].reverse()) {
            ctx.beginPath();
            // Build points: left edge → each bucket top → right edge
            const points: [number,number][] = [];
            for (let i = 0; i < BUCKETS; i++) {
                const x = pad.left + i * bw + bw / 2;
                const stackH = (stackBottom[i] + data[pr][i]) / maxVal * cH;
                points.push([x, pad.top + cH - stackH]);
            }
            // Smooth curve
            ctx.moveTo(points[0][0], points[0][1]);
            for (let i = 1; i < points.length - 1; i++) {
                const mx = (points[i][0] + points[i+1][0]) / 2;
                const my = (points[i][1] + points[i+1][1]) / 2;
                ctx.quadraticCurveTo(points[i][0], points[i][1], mx, my);
            }
            ctx.lineTo(points[points.length-1][0], points[points.length-1][1]);
            // Close to baseline
            const baseY = pad.top + cH;
            ctx.lineTo(pad.left + cW, baseY);
            ctx.lineTo(pad.left, baseY);
            ctx.closePath();
            ctx.fillStyle = colors[pr] ? colors[pr].replace(')', ', 0.35)').replace('rgb', 'rgba') : 'rgba(255,255,255,0.1)';
            if (colors[pr].startsWith('#')) {
                ctx.fillStyle = colors[pr] + '55';
            }
            ctx.fill();
            // Update stack
            for (let i = 0; i < BUCKETS; i++) stackBottom[i] += data[pr][i];
        }

        // Y-axis labels
        ctx.fillStyle = 'rgba(255,255,255,0.3)';
        ctx.font = `${9 * dpr / dpr}px monospace`;
        ctx.textAlign = 'right';
        for (let g = 0; g <= 4; g++) {
            const val = (g / 4) * maxVal;
            const y   = pad.top + cH - (g / 4) * cH;
            ctx.fillText(this.formatBytes(val), pad.left - 4, y + 3);
        }

        // X-axis: start / mid / end
        ctx.textAlign = 'center';
        ctx.fillText('0ms', pad.left, H - 4);
        const fmtMs = (ms: number) => ms < 1 ? `${(ms*1000).toFixed(0)}µs` : ms < 1000 ? `${ms.toFixed(1)}ms` : `${(ms/1000).toFixed(2)}s`;
        ctx.fillText(fmtMs(maxTs / 2), pad.left + cW / 2, H - 4);
        ctx.fillText(fmtMs(maxTs), pad.left + cW, H - 4);
    }

    protocolList(): { proto: string; count: number }[] {
        if (!this.pcapAnalysis) return [];
        return Object.entries(this.pcapAnalysis.protocols)
            .map(([proto, count]) => ({ proto, count: count as number }))
            .sort((a, b) => b.count - a.count);
    }

    formatBytes(b: number): string {
        if (b < 1024) return `${b} B`;
        if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
        return `${(b/1048576).toFixed(2)} MB`;
    }

    downloadPcap(session: any) {
        this.arkime.downloadPcap(session.id || session.session_id, session.sensor_host || '', session);
    }

    sessionDuration(s: any): string {
        if (!s.start_time || !s.end_time) return '—';
        const ms = s.end_time - s.start_time;
        if (ms < 1000) return `${ms}ms`;
        return `${(ms / 1000).toFixed(2)}s`;
    }

    ngOnInit() {
        this.sensorIds = this.auth.getSensorIds();
        const user = this.auth.getUser();
        this.currentUsername = user?.username || user?.name || '';
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
        this.isolateGateway = '';
        this.isolateEnforcement = 'arp';
        this.isolateVlan = 999;
        this.isolateReason = '';
        this.isolateError = '';
        this.showIsolateModal = true;
        // Pre-fill gateway from agent's own routing table
        this.api.getAgentStatus().subscribe({
            next: (s: any) => {
                if (s?.gateway) {
                    this.isolateGateway = s.gateway;
                    this.cdr.detectChanges();
                }
            },
            error: () => {}
        });
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

    // ─── Case Workflow ────────────────────────────────────────────────────────
    // States: New → Assigned → In Progress → Pending → Under Review → Resolved → Closed
    // Also: False Positive (from any active state)

    readonly WORKFLOW_STATES = [
        'New', 'Assigned', 'In Progress', 'Pending', 'Under Review', 'Resolved', 'Closed'
    ];
    readonly WORKFLOW_NEXT: Record<string, string[]> = {
        'New':           ['Assigned', 'In Progress', 'False Positive'],
        'Assigned':      ['In Progress', 'Pending', 'False Positive'],
        'In Progress':   ['Pending', 'Under Review', 'Resolved', 'False Positive'],
        'Pending':       ['In Progress', 'Resolved', 'Closed', 'False Positive'],
        'Under Review':  ['In Progress', 'Resolved', 'Closed', 'False Positive'],
        'Resolved':      ['Closed', 'In Progress'],
        'Closed':        ['New'],
        'False Positive': ['New'],
        'Evidence Collected': ['In Progress', 'Resolved', 'Closed', 'False Positive'],
    };

    nextStates(status: string): string[] {
        return this.WORKFLOW_NEXT[status] || ['In Progress'];
    }

    statusClass(status: string): string {
        switch (status) {
            case 'New':           return 'status-new';
            case 'Assigned':      return 'status-assigned';
            case 'In Progress':   return 'status-inprogress';
            case 'Pending':       return 'status-pending';
            case 'Under Review':  return 'status-review';
            case 'Resolved':      return 'status-resolved';
            case 'Closed':        return 'status-closed';
            case 'False Positive':return 'status-fp';
            default:              return 'status-inprogress';
        }
    }

    priorityClass(p: string): string {
        switch (p) {
            case 'P1': return 'prio-p1';
            case 'P2': return 'prio-p2';
            case 'P3': return 'prio-p3';
            default:   return 'prio-p4';
        }
    }

    priorityLabel(p: string): string {
        return { P1: 'P1 CRITICAL', P2: 'P2 HIGH', P3: 'P3 MEDIUM', P4: 'P4 LOW' }[p] || p;
    }

    // ─── Case Stats (computed from loaded cases) ─────────────────────────────
    get caseStats() {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayTs = Math.floor(today.getTime() / 1000);
        const active     = this.cases.filter(c => !['Closed', 'False Positive'].includes(c.status)).length;
        const inProgress = this.cases.filter(c => c.status === 'In Progress').length;
        const resolvedToday = this.cases.filter(c =>
            c.status === 'Resolved' && c.closed_at && c.closed_at >= todayTs
        ).length;

        const closed = this.cases.filter(c =>
            ['Resolved', 'Closed'].includes(c.status) && c.closed_at && c.created_at
        );
        const avgHrs = closed.length
            ? Math.round(closed.reduce((s, c) => s + (c.closed_at - c.created_at) / 3600, 0) / closed.length)
            : 0;

        return { active, inProgress, resolvedToday, avgHrs };
    }

    // ─── New Case Form ────────────────────────────────────────────────────────
    showNewCase = false;
    newCaseTitle = '';
    newCaseDescription = '';
    newCaseSeverity = 'HIGH';
    newCasePriority = 'P2';
    newCaseAssignedTo = '';
    newCaseSrcIp = '';
    newCaseDstIp = '';
    newCaseTags = '';
    newCaseError = '';
    savingNewCase = false;

    openNewCaseModal() {
        this.newCaseTitle = '';
        this.newCaseDescription = '';
        this.newCaseSeverity = 'HIGH';
        this.newCasePriority = 'P2';
        this.newCaseAssignedTo = this.currentUsername;
        this.newCaseSrcIp = '';
        this.newCaseDstIp = '';
        this.newCaseTags = '';
        this.newCaseError = '';
        this.showNewCase = true;
    }

    submitNewCase() {
        if (!this.newCaseTitle.trim()) { this.newCaseError = 'Title is required'; return; }
        this.savingNewCase = true;
        this.newCaseError = '';
        const tags = this.newCaseTags.split(',').map(t => t.trim()).filter(Boolean);
        this.api.createSoarCase({
            title: this.newCaseTitle.trim(),
            description: this.newCaseDescription.trim(),
            severity: this.newCaseSeverity,
            priority: this.newCasePriority,
            assigned_to: this.newCaseAssignedTo.trim(),
            src_ip: this.newCaseSrcIp.trim(),
            dst_ip: this.newCaseDstIp.trim(),
            tags,
        }).subscribe({
            next: (res: any) => {
                this.savingNewCase = false;
                if (res.status === 'success') {
                    this.showNewCase = false;
                    this.loadCases();
                    this.cdr.detectChanges();
                } else {
                    this.newCaseError = res.message || 'Failed to create case';
                    this.cdr.detectChanges();
                }
            },
            error: (err: any) => {
                this.savingNewCase = false;
                this.newCaseError = err.error?.message || 'Request failed';
                this.cdr.detectChanges();
            }
        });
    }

    // ─── Case Assignment Inline Edit ──────────────────────────────────────────
    editingAssignee = false;
    assigneeInput = '';

    startEditAssignee() {
        this.assigneeInput = this.selectedCase?.assigned_to || this.currentUsername;
        this.editingAssignee = true;
        this.cdr.detectChanges();
    }

    saveAssignee() {
        if (!this.selectedCase) return;
        this.editingAssignee = false;
        const assigned_to = this.assigneeInput.trim();
        const c = this.selectedCase;
        this.api.updateSoarCase(c.id, {
            title: c.title, description: c.description,
            assigned_to, priority: c.priority || 'P2', severity: c.severity || 'MEDIUM',
        }).subscribe({
            next: (res: any) => {
                if (res.status === 'success') {
                    this.selectedCase.assigned_to = assigned_to;
                    this.loadCases();
                }
                this.cdr.detectChanges();
            },
            error: () => this.cdr.detectChanges()
        });
    }

    // ─── Cases Logic ─────────────────────────────────────────────────────────
    openCase(c: any) {
        this.selectedCase = c;
        this.editingAssignee = false;
        this.liveEvidence = null;
        this.loadingCase = true;
        this.collectingPcap = false;
        this.collectPcapDone = false;
        // Reset all PCAP/session state so previous case's data doesn't bleed in
        this.pcapViewSession  = null;
        this.pcapPackets      = [];
        this.pcapError        = '';
        this.pcapLoading      = false;
        this.pcapNote         = '';
        this.selectedSession  = null;
        this.sessionNote      = '';
        this.expandedPktIdx   = new Set();
        this.incidentReport   = null;
        this.showCloseForm    = false;

        this.api.getSoarCaseComments(c.id).subscribe((res: any) => {
            if (res.status === 'success') {
                this.caseComments = res.data;
            }
            this.loadingCase = false;
            this.cdr.detectChanges();
        });

        this.dismissedSessionIds = new Set();
        const hasPair = c.src_ip && c.dst_ip;
        const hasCid  = !!c.community_id;
        if (hasPair || hasCid) {
            this.evidenceLoading = true;
            const pcapParams = hasPair
                ? { src_ip: c.src_ip, dst_ip: c.dst_ip, limit: 50 }
                : { cid: c.community_id, limit: 50 };
            this.arkime.getSessions(pcapParams).subscribe((pcap: any) => {
                this.liveEvidence = this.liveEvidence || {};
                this.liveEvidence.pcap_sessions = pcap.sessions || [];
                this.liveEvidence.pcap_total = pcap.total || pcap.sessions?.length || 0;
                this.evidenceLoading = false;
                this.cdr.detectChanges();
            });
            if (hasCid) {
                this.api.getEventsByCid(c.community_id).subscribe((res: any) => {
                    this.liveEvidence = this.liveEvidence || {};
                    this.liveEvidence.ndr_events = res.events || [];
                    this.cdr.detectChanges();
                });
            }
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

    formatDateShort(ts: any): string {
        if (!ts) return '-';
        const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
        return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    collectPcap() {
        const cid = this.selectedCase?.community_id;
        if (!cid || this.collectingPcap) return;
        this.collectingPcap = true;
        this.collectPcapDone = false;
        this.api.triggerEvidenceCapture(cid).subscribe({
            next: () => {
                this.collectingPcap = false;
                this.collectPcapDone = true;
                setTimeout(() => this.openCase(this.selectedCase), 4000);
            },
            error: () => {
                this.collectingPcap = false;
                this.collectPcapDone = true;
            },
        });
    }

    closeCaseModal() {
        this.selectedCase    = null;
        this.caseComments    = [];
        this.liveEvidence    = null;
        this.evidenceLoading = false;
        this.editingAssignee = false;
        this.collectingPcap  = false;
        this.collectPcapDone = false;
        this.pcapViewSession = null;
        this.pcapPackets     = [];
        this.pcapError       = '';
        this.pcapLoading     = false;
        this.pcapNote        = '';
        this.selectedSession = null;
        this.sessionNote     = '';
        this.expandedPktIdx  = new Set();
        this.incidentReport  = null;
        this.showCloseForm   = false;
    }

    updateCaseStatus(status: string) {
        if (!this.selectedCase) return;
        if (['Resolved', 'Closed'].includes(status)) {
            this.pendingStatus = status;
            this.closeNotes    = '';
            this.addToIntel    = !!this.selectedCase.src_ip;
            this.intelGroup    = (this.selectedCase.tags || []).join(', ');
            this.showCloseForm = true;
            this.cdr.detectChanges();
            return;
        }
        // Auto-assign to logged-in analyst when transitioning to Assigned with no assignee
        if (status === 'Assigned' && !this.selectedCase.assigned_to && this.currentUsername) {
            this.assigneeInput = this.currentUsername;
            this.saveAssignee();
        }
        this._doUpdateStatus(status);
    }

    confirmClose() {
        const c = this.selectedCase;
        if (!c) return;
        this._doUpdateStatus(this.pendingStatus);
        // Add attacker IP to threat intel watchlist if requested
        if (this.addToIntel && c.src_ip) {
            this.api.addManualIoc('ip', c.src_ip, this.intelGroup).subscribe();
        }
        // Generate incident report
        this.incidentReport = {
            case_number:  c.case_number,
            title:        c.title,
            severity:     c.severity,
            priority:     c.priority,
            src_ip:       c.src_ip,
            dst_ip:       c.dst_ip,
            status:       this.pendingStatus,
            analyst:      this.currentUsername,
            closed_at:    new Date().toLocaleString(),
            resolution:   this.closeNotes || 'No notes provided.',
            pcap_count:   this.liveEvidence?.pcap_sessions?.length || 0,
            tags:         (c.tags || []).join(', '),
            description:  c.description,
            intel_added:  this.addToIntel && c.src_ip ? `${c.src_ip} added to threat intel watchlist` : null,
        };
        // Add resolution note as case comment
        if (this.closeNotes.trim()) {
            this.api.addSoarCaseComment(c.id, `[${this.pendingStatus}] ${this.closeNotes}`).subscribe();
        }
        this.showCloseForm = false;
        this.cdr.detectChanges();
    }

    _doUpdateStatus(status: string) {
        if (!this.selectedCase) return;
        this.api.updateSoarCaseStatus(this.selectedCase.id, status).subscribe({
            next: (res: any) => {
                if (res.status === 'success') {
                    this.selectedCase.status = status;
                    if (['Resolved', 'Closed', 'False Positive'].includes(status)) {
                        this.selectedCase.closed_at = Math.floor(Date.now() / 1000);
                    } else {
                        this.selectedCase.closed_at = null;
                    }
                    this.cdr.detectChanges();
                    this.loadCases();
                }
            },
            error: (err) => {
                alert('Status update failed: ' + (err.error?.message || err.message));
            }
        });
    }

    addComment() {
        if (!this.newComment.trim() || !this.selectedCase) return;
        this.api.addSoarCaseComment(this.selectedCase.id, this.newComment).subscribe((res: any) => {
            if (res.status === 'success') {
                this.newComment = '';
                this.openCase(this.selectedCase);
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

    severityClass(sev: string): string {
        switch ((sev || '').toUpperCase()) {
            case 'CRITICAL': return 'sev-critical';
            case 'HIGH':     return 'sev-high';
            case 'MEDIUM':   return 'sev-medium';
            case 'LOW':      return 'sev-low';
            default:         return 'sev-low';
        }
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