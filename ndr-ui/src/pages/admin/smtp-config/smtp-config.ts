import { Component, OnInit, OnDestroy, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  AlertTriangle, CircleCheck, LoaderCircle, Save,
  Mail, Server, ShieldCheck, Lock, Send, KeyRound, Clock, Activity, RefreshCw, Eye, EyeOff, Zap, ShieldAlert
} from 'lucide-angular';
import { Api } from '../../../services/api/api';

@Component({
  selector: 'app-smtp-config',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './smtp-config.html',
  styleUrl: './smtp-config.css',
})
export class SmtpConfig implements OnInit, OnDestroy {
  Math = Math;

  CheckIcon       = CircleCheck;
  ErrorIcon       = AlertTriangle;
  LoadingIcon     = LoaderCircle;
  SaveIcon        = Save;
  MailIcon        = Mail;
  ServerIcon      = Server;
  ShieldIcon      = ShieldCheck;
  LockIcon        = Lock;
  SendIcon        = Send;
  KeyRoundIcon    = KeyRound;
  ClockIcon       = Clock;
  ActivityIcon    = Activity;
  RefreshIcon     = RefreshCw;
  EyeIcon         = Eye;
  EyeOffIcon      = EyeOff;
  ZapIcon         = Zap;
  ShieldAlertIcon = ShieldAlert;

  smtpConfig = { host: '', port: 587, user: '', password: '' };
  savingSmtp   = false;
  smtpMessage  = '';
  smtpError    = '';
  showPassword = false;

  currentTime = '';
  currentDate = '';
  private clockTimer: any = null;

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  get isConfigured(): boolean {
    return !!(this.smtpConfig.user && this.smtpConfig.host);
  }

  get tlsMode(): string {
    if (this.smtpConfig.port === 465) return 'Implicit SSL/TLS';
    if (this.smtpConfig.port === 587) return 'Explicit STARTTLS';
    return 'Opportunistic / Plain';
  }

  setPort(p: number) {
    this.smtpConfig.port = p;
  }

  private updateClock() {
    const now = new Date();
    this.currentTime = now.toLocaleTimeString('en-US', { hour12: false });
    this.currentDate = now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
    this.cdr.detectChanges();
  }

  ngOnInit() {
    this.updateClock();
    this.clockTimer = setInterval(() => this.updateClock(), 1000);
    this.loadSmtpConfig();
  }

  ngOnDestroy() {
    if (this.clockTimer) clearInterval(this.clockTimer);
  }

  loadSmtpConfig() {
    this.api.getGlobalSmtp().subscribe({
      next: (data: any) => {
        if (data.status === 'ok' && data.config) this.smtpConfig = data.config;
        this.cdr.detectChanges();
      },
      error: (err: any) => { console.error('Failed to load SMTP config', err); },
    });
  }

  saveSmtpConfig() {
    this.savingSmtp = true; this.smtpMessage = ''; this.smtpError = '';
    this.api.updateGlobalSmtp(this.smtpConfig).subscribe({
      next: () => {
        this.savingSmtp   = false;
        this.smtpMessage  = 'SMTP configuration saved';
        this.smtpConfig.password = '';
        this.loadSmtpConfig();
        this.cdr.detectChanges();
        setTimeout(() => { this.smtpMessage = ''; this.cdr.detectChanges(); }, 3000);
      },
      error: () => {
        this.savingSmtp  = false;
        this.smtpError   = 'Failed to save SMTP configuration';
        this.cdr.detectChanges();
      },
    });
  }
}
