import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import { AuthService } from '../../services/auth/auth';
import {
    LucideAngularModule,
    AlertTriangle,
    Bell,
    Bot,
    CheckCircle2,
    Database,
    Eye,
    EyeOff,
    KeyRound,
    LoaderCircle,
    Save,
    ShieldAlert,
    SlidersHorizontal,
    Workflow
} from 'lucide-angular';

@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, FormsModule, LucideAngularModule],
    templateUrl: './settings.html',
    styleUrl: './settings.css'
})
export class Settings implements OnInit {
    loading    = true;
    saving     = false;
    savingAi   = false;
    message    = '';
    error      = '';
    aiMessage  = '';
    aiError    = '';
    showApiKey = false;

    isSuperAdmin = false;

    thresholds = {
        store_threshold:    10,
        alert_threshold:    75,
        critical_threshold: 90,
        soar_threshold:     75
    };

    aiConfig = {
        ai_provider:      'openai',
        ai_api_key:       '',
        ai_model:         '',
        ai_base_url:      '',
        ai_endpoint_path: '',
        ai_msg_format:    'openai',
        ai_key_set:       false
    };

    providerOptions = [
        { value: 'openai',     label: 'OpenAI (gpt-4o-mini)' },
        { value: 'anthropic',  label: 'Anthropic (claude-sonnet-4-6)' },
        { value: 'custom',     label: 'Custom / Local (OpenAI-compatible)' },
    ];

    SlidersIcon  = SlidersHorizontal;
    SaveIcon     = Save;
    CheckIcon    = CheckCircle2;
    ErrorIcon    = AlertTriangle;
    DatabaseIcon = Database;
    BellIcon     = Bell;
    CriticalIcon = ShieldAlert;
    WorkflowIcon = Workflow;
    LoadingIcon  = LoaderCircle;
    BotIcon      = Bot;
    KeyIcon      = KeyRound;
    EyeIcon      = Eye;
    EyeOffIcon   = EyeOff;

    constructor(
        private api: Api,
        private auth: AuthService,
        private cdr: ChangeDetectorRef
    ) {}

    ngOnInit() {
        const user = this.auth.getUser();
        this.isSuperAdmin = user?.role === 'super_admin';
        this.loadSettings();
        if (this.isSuperAdmin) {
            this.loadAiConfig();
        }
    }

    loadSettings() {
        this.api.getSettings().subscribe({
            next: (data: any) => {
                const s = data.settings || {};
                this.thresholds = {
                    store_threshold:    s.store_threshold    ?? 10,
                    alert_threshold:    s.alert_threshold    ?? 75,
                    critical_threshold: s.critical_threshold ?? 90,
                    soar_threshold:     s.soar_threshold     ?? 75,
                };
                this.loading = false;
                this.cdr.detectChanges();
            },
            error: () => {
                this.loading = false;
                this.cdr.detectChanges();
            }
        });
    }

    loadAiConfig() {
        this.api.getAiConfig().subscribe({
            next: (data: any) => {
                this.aiConfig = {
                    ai_provider:      data.ai_provider      || 'openai',
                    ai_api_key:       '',
                    ai_model:         data.ai_model         || '',
                    ai_base_url:      data.ai_base_url      || '',
                    ai_endpoint_path: data.ai_endpoint_path || '',
                    ai_msg_format:    data.ai_msg_format     || 'openai',
                    ai_key_set:       data.ai_key_set        || false
                };
                this.cdr.detectChanges();
            },
            error: () => {}
        });
    }

    saveSettings() {
        this.saving = true;
        this.message = '';
        this.error = '';
        this.api.updateSettings(this.thresholds).subscribe({
            next: () => {
                this.saving = false;
                this.message = 'Settings saved';
                this.cdr.detectChanges();
                setTimeout(() => {
                    this.message = '';
                    this.cdr.detectChanges();
                }, 3000);
            },
            error: () => {
                this.saving = false;
                this.error = 'Failed to save settings';
                this.cdr.detectChanges();
            }
        });
    }

    saveAiConfig() {
        this.savingAi = true;
        this.aiMessage = '';
        this.aiError = '';
        const payload: any = {
            ai_provider:      this.aiConfig.ai_provider,
            ai_model:         this.aiConfig.ai_model,
            ai_base_url:      this.aiConfig.ai_base_url,
            ai_endpoint_path: this.aiConfig.ai_endpoint_path,
            ai_msg_format:    this.aiConfig.ai_msg_format,
        };
        // Only send key if user typed something new
        if (this.aiConfig.ai_api_key.trim()) {
            payload.ai_api_key = this.aiConfig.ai_api_key.trim();
        }
        this.api.updateAiConfig(payload).subscribe({
            next: () => {
                this.savingAi = false;
                this.aiMessage = 'AI configuration saved';
                this.aiConfig.ai_key_set = this.aiConfig.ai_key_set ||
                    !!this.aiConfig.ai_api_key.trim();
                this.aiConfig.ai_api_key = '';
                this.cdr.detectChanges();
                setTimeout(() => {
                    this.aiMessage = '';
                    this.cdr.detectChanges();
                }, 3000);
            },
            error: () => {
                this.savingAi = false;
                this.aiError = 'Failed to save AI configuration';
                this.cdr.detectChanges();
            }
        });
    }

    get defaultModelHint(): string {
        switch (this.aiConfig.ai_provider) {
            case 'anthropic': return 'Default: claude-sonnet-4-6';
            case 'custom':    return 'e.g. llama3, mistral, deepseek-r1';
            default:          return 'Default: gpt-4o-mini';
        }
    }
}
