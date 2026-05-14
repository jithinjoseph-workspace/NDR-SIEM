import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';

@Component({
    selector: 'app-settings',
    standalone: true,
    imports: [CommonModule, FormsModule],
    templateUrl: './settings.html',
    styleUrl: './settings.css'
})
export class Settings implements OnInit {
    loading = true;
    saving  = false;
    message = '';
    error   = '';

    thresholds = {
        store_threshold:    10,
        alert_threshold:    75,
        critical_threshold: 90,
        soar_threshold:     75
    };

    constructor(
        private api: Api,
        private cdr: ChangeDetectorRef
    ) {}

    ngOnInit() {
        this.loadSettings();
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

    saveSettings() {
        this.saving = true;
        this.message = '';
        this.error = '';
        this.api.updateSettings(this.thresholds).subscribe({
            next: (data: any) => {
                this.saving = false;
                this.message = '✅ Settings saved!';
                this.cdr.detectChanges();
                setTimeout(() => {
                    this.message = '';
                    this.cdr.detectChanges();
                }, 3000);
            },
            error: () => {
                this.saving = false;
                this.error = '❌ Failed to save settings';
                this.cdr.detectChanges();
            }
        });
    }
}