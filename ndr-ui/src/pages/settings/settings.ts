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
    Plus,
    Save,
    ShieldAlert,
    SlidersHorizontal,
    Trash2,
    Workflow,
    Zap
} from 'lucide-angular';

interface AiProvider {
    name: string;
    provider_type: string;
    model: string;
    base_url: string;
    use_case: string;
    priority: number;
    enabled: boolean;
    key_set: boolean;
}

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
    message    = '';
    error      = '';

    // AI provider list
    providers: AiProvider[]  = [];
    loadingProviders         = false;
    savingProvider           = false;
    providerMessage          = '';
    providerError            = '';
    showAddForm              = false;
    testingProvider          = '';
    testResult               = '';
    showProviderKey          = false;

    isSuperAdmin = false;

    thresholds = {
        store_threshold:    10,
        alert_threshold:    75,
        critical_threshold: 90,
        soar_threshold:     75
    };

    // Form for adding/editing a provider
    newProvider = {
        name:          '',
        provider_type: 'custom',
        api_key:       '',
        model:         '',
        base_url:      '',
        endpoint_path: '/v1/chat/completions',
        msg_format:    'openai',
        use_case:      'all',
        priority:      10,
        enabled:       true,
    };

    providerTypeOptions = [
        { value: 'custom',    label: 'Custom / OpenAI-compatible' },
        { value: 'openai',    label: 'OpenAI' },
        { value: 'anthropic', label: 'Anthropic' },
    ];

    useCaseOptions = [
        { value: 'all',    label: 'All (chat + threat analysis)' },
        { value: 'chat',   label: 'ARIA chat only' },
        { value: 'threat', label: 'Threat analysis only' },
    ];

    // Legacy single-provider config (kept for backwards compat)
    aiConfig = {
        ai_provider:      'custom',
        ai_api_key:       '',
        ai_model:         '',
        ai_base_url:      '',
        ai_endpoint_path: '',
        ai_msg_format:    'openai',
        ai_key_set:       false
    };

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
    PlusIcon     = Plus;
    TrashIcon    = Trash2;
    TestIcon     = Zap;

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
            this.loadProviders();
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

    loadProviders() {
        this.loadingProviders = true;
        this.api.listAiProviders().subscribe({
            next: (data: any) => {
                this.providers = data.providers || [];
                this.loadingProviders = false;
                this.cdr.detectChanges();
            },
            error: () => {
                this.loadingProviders = false;
                this.cdr.detectChanges();
            }
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
                setTimeout(() => { this.message = ''; this.cdr.detectChanges(); }, 3000);
            },
            error: () => {
                this.saving = false;
                this.error = 'Failed to save settings';
                this.cdr.detectChanges();
            }
        });
    }

    saveProvider() {
        this.savingProvider = true;
        this.providerMessage = '';
        this.providerError   = '';
        this.api.saveAiProvider(this.newProvider).subscribe({
            next: () => {
                this.savingProvider  = false;
                this.providerMessage = `Provider "${this.newProvider.name}" saved`;
                this.showAddForm     = false;
                this.resetNewProvider();
                this.loadProviders();
                this.cdr.detectChanges();
                setTimeout(() => { this.providerMessage = ''; this.cdr.detectChanges(); }, 3000);
            },
            error: () => {
                this.savingProvider = false;
                this.providerError  = 'Failed to save provider';
                this.cdr.detectChanges();
            }
        });
    }

    deleteProvider(name: string) {
        if (!confirm(`Delete provider "${name}"?`)) return;
        this.api.deleteAiProvider(name).subscribe({
            next: () => {
                this.providerMessage = `Provider "${name}" deleted`;
                this.loadProviders();
                this.cdr.detectChanges();
                setTimeout(() => { this.providerMessage = ''; this.cdr.detectChanges(); }, 3000);
            },
            error: () => {
                this.providerError = 'Failed to delete provider';
                this.cdr.detectChanges();
            }
        });
    }

    testProvider(p: AiProvider) {
        this.testingProvider = p.name;
        this.testResult      = '';
        // We only test with the current form data if it's the one being added
        const payload = {
            name:          p.name,
            provider_type: p.provider_type,
            api_key:       '',   // server will use stored key
            model:         p.model,
            base_url:      p.base_url,
            endpoint_path: '/v1/chat/completions',
            msg_format:    'openai',
        };
        this.api.testAiProvider(payload).subscribe({
            next: (data: any) => {
                this.testingProvider = '';
                this.testResult      = data.status === 'ok'
                    ? `✓ ${p.name} — OK`
                    : `✗ ${p.name} — ${data.error}`;
                this.cdr.detectChanges();
                setTimeout(() => { this.testResult = ''; this.cdr.detectChanges(); }, 5000);
            },
            error: () => {
                this.testingProvider = '';
                this.testResult      = `✗ ${p.name} — request failed`;
                this.cdr.detectChanges();
                setTimeout(() => { this.testResult = ''; this.cdr.detectChanges(); }, 5000);
            }
        });
    }

    testNewProvider() {
        this.testingProvider = '__new__';
        this.testResult      = '';
        this.api.testAiProvider(this.newProvider).subscribe({
            next: (data: any) => {
                this.testingProvider = '';
                this.testResult      = data.status === 'ok'
                    ? '✓ Connection OK — ' + (data.response || '').substring(0, 60)
                    : '✗ ' + (data.error || 'No response');
                this.cdr.detectChanges();
                setTimeout(() => { this.testResult = ''; this.cdr.detectChanges(); }, 6000);
            },
            error: () => {
                this.testingProvider = '';
                this.testResult      = '✗ Request failed — check URL and key';
                this.cdr.detectChanges();
            }
        });
    }

    resetNewProvider() {
        this.newProvider = {
            name: '', provider_type: 'custom', api_key: '', model: '',
            base_url: '', endpoint_path: '/v1/chat/completions',
            msg_format: 'openai', use_case: 'all', priority: 10, enabled: true,
        };
    }

    get defaultBaseUrl(): string {
        switch (this.newProvider.provider_type) {
            case 'openai':    return 'https://api.openai.com';
            case 'anthropic': return 'https://api.anthropic.com';
            default:          return '';
        }
    }

    get defaultModelPlaceholder(): string {
        switch (this.newProvider.provider_type) {
            case 'openai':    return 'gpt-4o-mini';
            case 'anthropic': return 'claude-sonnet-4-6';
            default:          return 'e.g. llama-3.3-70b-versatile';
        }
    }

    useCaseLabel(uc: string): string {
        return { all: 'All', chat: 'Chat', threat: 'Threat' }[uc] || uc;
    }
}
