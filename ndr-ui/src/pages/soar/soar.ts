import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import {
    LucideAngularModule,
    Zap, Play, Pause, Settings,
    CheckCircle, XCircle, Link,
    RefreshCw, ExternalLink, Plus,
    Trash2, Bell, Mail, Globe
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

    view = 'check';
    loading = true;

    // Setup
    shuffleUrl = 'http://localhost:5001';
    username = 'admin';
    password = '';
    setting = false;
    setupError = '';
    setupMsg = '';

    // Connected state
    soarConnected = false;
    webhookUrl = '';
    shuffleUiUrl = '';

    // Playbooks
    playbooks: any[] = [];

    // Recent executions
    recentActions: any[] = [];

    // Notification actions
    showNewAction = false;
    actionType = 'slack';
    actionName = '';
    actionWebhook = '';
    actionEmail = '';
    actionTrigger = 'score > 75';
    savingAction = false;
    actionMsg = '';

    // Settings
    showSettings = false;
    manualWebhook = '';
    manualShuffleUrl = '';

    //SOAR Integrations
    
    integrations: any[] = [];
showNewIntegration = false;
intType     = 'slack';
intName     = '';
intConfig: any = {};
testingInt  = false;
testResult  = '';
savingInt   = false;


integrationTypes = [
    { 
        type: 'slack', 
        name: 'Slack',
        icon: '💬',
        fields: [
            { key: 'webhook_url', label: 'Webhook URL', 
              placeholder: 'https://hooks.slack.com/...' }
        ]
    },
    { 
        type: 'teams', 
        name: 'Microsoft Teams',
        icon: '🟦',
        fields: [
            { key: 'webhook_url', label: 'Webhook URL',
              placeholder: 'https://outlook.office.com/webhook/...' }
        ]
    },
    { 
        type: 'discord', 
        name: 'Discord',
        icon: '🎮',
        fields: [
            { key: 'webhook_url', label: 'Webhook URL',
              placeholder: 'https://discord.com/api/webhooks/...' }
        ]
    },
    { 
        type: 'telegram', 
        name: 'Telegram',
        icon: '✈️',
        fields: [
            { key: 'bot_token', label: 'Bot Token',
              placeholder: '1234567890:ABC...' },
            { key: 'chat_id', label: 'Chat ID',
              placeholder: '-1001234567890' }
        ]
    },
    { 
        type: 'pagerduty', 
        name: 'PagerDuty',
        icon: '🚨',
        fields: [
            { key: 'routing_key', label: 'Routing Key',
              placeholder: 'abc123...' }
        ]
    },

    {
    type: 'jira',
    name: 'Jira',
    icon: '🎫',
    fields: [
        { key: 'url', label: 'Jira URL',
          placeholder: 'https://yoursite.atlassian.net' },
        { key: 'email', label: 'Email',
          placeholder: 'your@email.com' },
        { key: 'token', label: 'API Token',
          placeholder: 'ATATT3x...' },
        { key: 'project_key', label: 'Project Key',
          placeholder: 'NAR' }
    ]
},
    { 
        type: 'webhook', 
        name: 'Custom Webhook',
        icon: '🔗',
        fields: [
            { key: 'webhook_url', label: 'Webhook URL',
              placeholder: 'https://your-endpoint.com/alert' }
        ]
    }
];


    constructor(
        private api: Api,
        private cdr: ChangeDetectorRef
    ) { }

    ngOnInit() {
        this.checkStatus();
    }

    checkStatus() {
        this.loading = true;
        this.api.getSoarStatus().subscribe({
            next: (data: any) => {
                this.soarConnected = data.connected || false;
                this.webhookUrl = data.webhook_url || '';
                this.shuffleUiUrl = data.shuffle_url || '';
                this.playbooks = data.playbooks || [];
                this.loading = false;
                if (this.webhookUrl) {
                    this.view = 'connected';
                    this.loadExecutions();
                    this.loadIntegrations(); 
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

getIntIcon(type: string): string {
    const icons: any = {
        'slack':     '💬',
        'teams':     '🟦',
        'discord':   '🎮',
        'telegram':  '✈️',
        'pagerduty': '🚨',
        'webhook':   '🔗',
        'email':     '📧'
    };
    return icons[type] || '🔔';
}

    setupSoar() {
        if (!this.shuffleUrl || !this.username || !this.password) {
            this.setupError = 'Please fill all fields!';
            return;
        }
        this.setting = true;
        this.setupError = '';
        this.setupMsg = 'Connecting to Shuffle...';
        this.cdr.detectChanges();

        this.api.setupSoar({
            shuffle_url: this.shuffleUrl,
            username: this.username,
            password: this.password,
        }).subscribe({
            next: (data: any) => {
                this.setting = false;
                if (data.status === 'ok') {
                    this.webhookUrl = data.webhook_url;
                    this.shuffleUiUrl = this.shuffleUrl
                        .replace(':5001', ':3002');
                    this.view = 'connected';
                    this.setupMsg = '✅ ' + data.message;
                    this.checkStatus();
                } else {
                    this.setupError = data.message;
                }
                this.cdr.detectChanges();
            },
            error: () => {
                this.setting = false;
                this.setupError = 'Connection failed — check URL and credentials';
                this.cdr.detectChanges();
            }
        });
    }

    loadExecutions() {
        this.api.getSoarExecutions().subscribe({
            next: (data: any) => {
                const execs = data.executions || [];
                if (Array.isArray(execs)) {
                    this.recentActions = execs
                        .slice(0, 10)
                        .map((e: any) => {
                            try {
                                const arg = JSON.parse(
                                    e.execution_argument || '{}'
                                );
                                return {
                                    name: `${arg.severity || 'ALERT'}: ${arg.src_ip} → ${arg.dst_ip}`,
                                    time: new Date((e.started_at || 0) * 1000).toLocaleString(),
                                    status: e.status,
                                    score: arg.score
                                };
                            } catch { return null; }
                        })
                        .filter((e: any) => e !== null);
                    this.cdr.detectChanges();
                }
            }
        });
    }

    togglePlaybook(pb: any) {
        pb.enabled = !pb.enabled;
        this.api.togglePlaybook({
            id: pb.id,
            enabled: pb.enabled
        }).subscribe({
            next: () => this.checkStatus()
        });
    }

    saveAction() {
        this.savingAction = true;
        this.actionMsg = '';

        // Build action config
        const action_config: any = {
            trigger: this.actionTrigger
        };

        if (this.actionType === 'slack') {
            action_config.webhook_url = this.actionWebhook;
        } else if (this.actionType === 'email') {
            action_config.email = this.actionEmail;
        } else if (this.actionType === 'webhook') {
            action_config.url = this.actionWebhook;
        }

        // Save as playbook to DB
        this.api.createPlaybook({
            name: this.actionType === 'slack'
                ? 'Slack Alert'
                : this.actionType === 'email'
                    ? 'Email Alert'
                    : 'Webhook Alert',
            description: `Send ${this.actionType} when ${this.actionTrigger}`,
            trigger: this.actionTrigger,
            action_type: this.actionType,
            action_config: action_config
        }).subscribe({
            next: (data: any) => {
                this.savingAction = false;
                this.showNewAction = false;
                this.actionWebhook = '';
                this.actionEmail = '';
                this.actionName = '';
                this.checkStatus();
                this.cdr.detectChanges();
            },
            error: () => {
                this.savingAction = false;
                this.actionMsg = '❌ Failed to save';
                this.cdr.detectChanges();
            }
        });
    }
    testWebhook() {
        this.api.testSoarWebhook().subscribe({
            next: (data: any) => {
                alert(data.status === 'ok'
                    ? '✅ Test alert sent!'
                    : '❌ ' + data.message);
            }
        });
    }

    openShuffle() {
        const url = this.shuffleUiUrl ||
            this.shuffleUrl.replace(':5001', ':3002');
        window.open(url, '_blank');
    }

    reconfigure() {
        this.showSettings = true;
        this.manualWebhook = this.webhookUrl;
        this.manualShuffleUrl = this.shuffleUiUrl;
        this.cdr.detectChanges();
    }

    saveManualConfig() {
        this.api.updateSoarConfig({
            webhook_url: this.manualWebhook,
            shuffle_url: this.manualShuffleUrl,
        }).subscribe({
            next: () => {
                this.webhookUrl = this.manualWebhook;
                this.shuffleUiUrl = this.manualShuffleUrl;
                this.showSettings = false;
                this.view = 'connected';
                this.cdr.detectChanges();
            }
        });
    }

    // helper used in template
    get emailAddress(): string { return this.actionEmail; }
    set emailAddress(v: string) { this.actionEmail = v; }

    get activeCount(): number {
        return this.playbooks.filter(p => p.enabled).length;
    }

    statusColor(status: string): string {
        switch (status) {
            case 'FINISHED': return 'text-primary';
            case 'EXECUTING': return 'text-yellow-400';
            case 'ABORTED': return 'text-red-400';
            default: return 'text-on-surface-variant';
        }
    }

    statusBg(status: string): string {
        switch (status) {
            case 'FINISHED': return 'bg-primary/20 text-primary';
            case 'EXECUTING': return 'bg-yellow-500/20 text-yellow-400';
            case 'ABORTED': return 'bg-red-500/20 text-red-400';
            default: return 'bg-surface-container text-on-surface-variant';
        }
    }


get selectedIntType() {
    return this.integrationTypes
        .find(t => t.type === this.intType);
}

loadIntegrations() {
    this.api.getIntegrations().subscribe({
        next: (data: any) => {
            this.integrations = data.integrations || [];
            this.cdr.detectChanges();
        }
    });
}

testIntegration() {
    this.testingInt = true;
    this.testResult = '';
    this.api.testIntegration({
        type:   this.intType,
        config: this.intConfig
    }).subscribe({
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
        name:   this.intName || this.selectedIntType?.name,
        type:   this.intType,
        config: this.intConfig
    }).subscribe({
        next: (data: any) => {
            this.savingInt          = false;
            this.showNewIntegration = false;
            this.intConfig          = {};
            this.intName            = '';
            this.loadIntegrations();
            this.cdr.detectChanges();
        },
        error: () => {
            this.savingInt = false;
            this.cdr.detectChanges();
        }
    });
}

toggleIntegration(int: any) {
    int.enabled = !int.enabled;
    this.api.toggleIntegration({
        id:      int.id,
        enabled: int.enabled
    }).subscribe();
}

deleteIntegration(int: any) {
    if (!confirm(`Delete ${int.name}?`)) return;
    this.api.deleteIntegration({ id: int.id })
        .subscribe({
            next: () => this.loadIntegrations()
        });
}

}