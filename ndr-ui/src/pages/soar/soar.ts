import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { Api } from '../../services/api/api';
import { LucideAngularModule,
    Zap, Play, Pause, Settings,
    CheckCircle, XCircle, Bell } from 'lucide-angular';

@Component({
    selector: 'app-soar',
    standalone: true,
    imports: [CommonModule, LucideAngularModule, FormsModule],
    templateUrl: './soar.html',
    styleUrl: './soar.css'
})
export class Soar implements OnInit {
    ZapIcon          = Zap;
    PlayIcon         = Play;
    PauseIcon        = Pause;
    SettingsIcon     = Settings;
    CheckCircleIcon  = CheckCircle;
    XCircleIcon      = XCircle;
    BellIcon         = Bell;

    shuffleUrl    = '';
    webhookUrl    = '';
    soarConnected = false;
    loading       = true;
    recentActions: any[] = [];

    // Default playbooks shown in NDR UI
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

    constructor(
        private api: Api,
        private http: HttpClient,
        private cdr: ChangeDetectorRef
    ) {}

    ngOnInit() {
        this.loadSoarStatus();
    }

    loadSoarStatus() {
        this.loading = true;
        this.api.getSoarStatus().subscribe({
            next: (data: any) => {
                this.shuffleUrl    = data.shuffle_url || '';
                this.webhookUrl    = data.webhook_url || '';
                this.soarConnected = data.connected || false;
                this.recentActions = data.recent_actions || [];
                this.loading = false;
                this.cdr.detectChanges();
            },
            error: () => {
                this.loading = false;
                this.cdr.detectChanges();
            }
        });
    }

    togglePlaybook(pb: any) {
        pb.enabled = !pb.enabled;
        this.cdr.detectChanges();
    }

    openShuffle() {
        window.open(this.shuffleUrl || 'http://localhost:3002', '_blank');
    }

    testWebhook() {
        this.api.testSoarWebhook().subscribe({
            next: () => alert('✅ Test alert sent to Shuffle!'),
            error: () => alert('❌ Webhook not configured')
        });
    }
}