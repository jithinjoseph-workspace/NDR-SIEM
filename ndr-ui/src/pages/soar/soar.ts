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


    showSlackInput = false;
    showEmailInput = false;
    slackWebhook   = '';
    emailAddress   = '';


    playbooks: any[] = [];

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
    this.loadExecutions();
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
    this.api.togglePlaybook({
        id:      pb.id,
        enabled: pb.enabled
    }).subscribe();
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
                                time: new Date(
                                    (e.started_at || 0) * 1000
                                ).toLocaleString(),
                                status: e.status,
                                score: arg.score
                            };
                        } catch {
                            return null;
                        }
                    })
                    .filter((e: any) => e !== null);
                this.cdr.detectChanges();
            }
        }
    });
}

saveSlack() {
    this.api.configureSoarSlack({
        webhook_url: this.slackWebhook
    }).subscribe({
        next: (data: any) => {
            if (data.status === 'ok') {
                this.showSlackInput = false;
                alert('✅ Slack configured!');
            }
        }
    });
}

saveEmail() {
    this.api.configureSoarEmail({
        email: this.emailAddress
    }).subscribe({
        next: (data: any) => {
            if (data.status === 'ok') {
                this.showEmailInput = false;
                alert('✅ Email configured!');
            }
        }
    });
}


loadSoarStatus() {
    this.api.getSoarStatus().subscribe({
        next: (data: any) => {
            this.soarConnected = data.connected;
            this.webhookUrl    = data.webhook_url;
            this.playbooks     = data.playbooks || [];
            
            if (this.webhookUrl) {
                this.view = 'connected';
                this.loadExecutions();
            } else {
                this.view = 'setup';
            }
            this.cdr.detectChanges();
        }
    });
}

}