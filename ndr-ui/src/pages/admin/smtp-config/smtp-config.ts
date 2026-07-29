import { Component, OnInit, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  AlertTriangle, CircleCheck, LoaderCircle, Save,
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
export class SmtpConfig implements OnInit {
  CheckIcon   = CircleCheck;
  ErrorIcon   = AlertTriangle;
  LoadingIcon = LoaderCircle;
  SaveIcon    = Save;

  smtpConfig = { host: 'smtp.gmail.com', port: 587, user: '', password: '' };
  savingSmtp  = false;
  smtpMessage = '';
  smtpError   = '';

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() { this.loadSmtpConfig(); }

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
