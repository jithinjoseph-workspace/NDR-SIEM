import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { LucideAngularModule,
    Zap, Play, Pause, Settings,
    CheckCircle, XCircle, Link,
    RefreshCw, ExternalLink } from 'lucide-angular';

@Component({
    selector: 'app-soar',
    standalone: true,
    imports: [CommonModule, LucideAngularModule, FormsModule],
    templateUrl: './soar.html',
    styleUrl: './soar.css'
})
export class Soar implements OnInit {
    ZapIcon         = Zap;
    PlayIcon        = Play;
    PauseIcon       = Pause;
    SettingsIcon    = Settings;
    CheckIcon       = CheckCircle;
    XIcon           = XCircle;
    LinkIcon        = Link;
    RefreshIcon     = RefreshCw;
    ExternalIcon    = ExternalLink;

    // Setup wizard steps
    // 'check' | 'setup' | 'connected' | 'settings'
    view = 'check';

    // Setup form
    shuffleUrl = 'http://localhost:5001';
    username   = 'admin';
    password   = '';
    setting    = false;
    setupError = '';
    setupMsg   = '';

    // Connected state
    soarConnected = false;
    webhookUrl    = '';
    shuffleUiUrl  = '';
    loading       = true;

    // Manual config
    manualWebhook  = '';
    manualShuffleUrl = '';
    showSettings   = false;

    playbooks = [
        {
            id: 1,
            name: 'High Severity Alert → Slack',
            description: 'Send Slack message when score > 75',
            trigger: 'Score > 75',
            enabled: true,
            runs: 0,
        },
        {
            id: 2,
            name: 'Malicious IP → Block + Email',
            description: 'Auto-block and send email alert',
            trigger: 'Threat Intel match',
            enabled: true,
            runs: 0,
        },
        {
            id: 3,
            name: 'Critical Alert → PagerDuty',
            description: 'Page on-call when score > 90',
            trigger: 'Score > 90',
            enabled: false,
            runs: 0,
        },
        {
            id: 4,
            name: 'Alert → Jira Ticket',
            description: 'Create Jira incident ticket',
            trigger: 'Any alert',
            enabled: false,
            runs: 0,
        },
    ];

    recentActions: any[] = [];

    constructor(
        private api: Api,
        private cdr: ChangeDetectorRef
    ) {}

    ngOnInit() {
        this.checkStatus();
    }

    checkStatus() {
        this.loading = true;
        this.api.getSoarStatus().subscribe({
            next: (data: any) => {
                this.soarConnected = data.connected || false;
                this.webhookUrl    = data.webhook_url || '';
                this.shuffleUiUrl  = data.shuffle_url || '';
                this.recentActions = data.recent_actions || [];
                this.loading = false;

                // Decide which view to show
                if (this.webhookUrl) {
                    this.view = 'connected';
                } else {
                    this.view = 'setup';
                }
                this.cdr.detectChanges();
            },
            error: () => {
                this.loading = false;
                this.view = 'setup';
                this.cdr.detectChanges();
            }
        });
    }

    setupSoar() {
        if (!this.shuffleUrl || !this.username || !this.password) {
            this.setupError = 'Please fill all fields!';
            return;
        }

        this.setting   = true;
        this.setupError = '';
        this.setupMsg  = 'Connecting to Shuffle...';
        this.cdr.detectChanges();

        this.api.setupSoar({
            shuffle_url: this.shuffleUrl,
            username:    this.username,
            password:    this.password,
        }).subscribe({
            next: (data: any) => {
                this.setting = false;
                if (data.status === 'ok') {
                    this.webhookUrl   = data.webhook_url;
                    this.shuffleUiUrl = this.shuffleUrl
                        .replace(':5001', ':3002');
                    this.view = 'connected';
                    this.setupMsg = '✅ ' + data.message;
                } else {
                    this.setupError = data.message;
                }
                this.cdr.detectChanges();
            },
            error: (err: any) => {
                this.setting = false;
                this.setupError = 'Connection failed — check URL and credentials';
                this.cdr.detectChanges();
            }
        });
    }

    saveManualConfig() {
        this.api.updateSoarConfig({
            webhook_url: this.manualWebhook,
            shuffle_url: this.manualShuffleUrl,
        }).subscribe({
            next: () => {
                this.webhookUrl   = this.manualWebhook;
                this.shuffleUiUrl = this.manualShuffleUrl;
                this.showSettings = false;
                this.view = 'connected';
                this.cdr.detectChanges();
            }
        });
    }

    testWebhook() {
        this.api.testSoarWebhook().subscribe({
            next: (data: any) => {
                alert(data.status === 'ok'
                    ? '✅ Test alert sent to Shuffle!'
                    : '❌ ' + data.message);
            },
            error: () => alert('❌ Webhook test failed')
        });
    }

    togglePlaybook(pb: any) {
        pb.enabled = !pb.enabled;
        this.cdr.detectChanges();
    }

    openShuffle() {
        const url = this.shuffleUiUrl ||
            this.shuffleUrl.replace(':5001', ':3002');
        window.open(url, '_blank');
    }

    reconfigure() {
        this.showSettings = true;
        this.manualWebhook    = this.webhookUrl;
        this.manualShuffleUrl = this.shuffleUiUrl;
        this.cdr.detectChanges();
    }
}