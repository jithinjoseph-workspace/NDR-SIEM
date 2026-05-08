import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../services/api/api';
import {
  LucideAngularModule,
  Globe, Search, Shield, Save, Upload, RefreshCw,
  Sun, Moon, ChevronRight, Check, AlertTriangle
} from 'lucide-angular';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './settings.html',
  styleUrl: './settings.css'
})
export class Settings implements OnInit {
  // Icons
  GlobeIcon = Globe;
  SearchIcon = Search;
  ShieldIcon = Shield;
  SaveIcon = Save;
  UploadIcon = Upload;
  RefreshIcon = RefreshCw;
  SunIcon = Sun;
  MoonIcon = Moon;
  ChevronIcon = ChevronRight;
  CheckIcon = Check;
  AlertIcon = AlertTriangle;

  // Tab navigation
  activeSection: 'general' | 'detection' | 'threat' = 'general';

  // Save state
  saving = false;
  saveSuccess = false;
  saveError = '';

  // Upload state
  uploading = false;
  uploadResult: any = null;
  dragOver = false;

  // Settings model
  settings: any = {
    // General
    org_name: 'NDR Command',
    system_name: 'Tactical Observatory',
    theme: 'dark',

    // Detection
    auto_block_threshold: 90,
    severity_critical: 90,
    severity_high: 75,
    severity_medium: 50,
    severity_low: 25,
    sigma_rules_dir: 'rules',
    hot_reload_interval_min: 5,

    // Threat Intelligence
    ti_refresh_interval_min: 60,
    feed_feodo_enabled: true,
    feed_malwarebazaar_enabled: true,
    feed_urlhaus_enabled: true,
    custom_ioc_feed_url: ''
  };
  loading = true;

  constructor(
    private api: Api,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadSettings();
  }

  loadSettings() {
    this.loading = true;
    this.api.getSettings().subscribe({
      next: (data: any) => {
        if (data && typeof data === 'object') {
          // Merge server settings into local model
          Object.keys(this.settings).forEach(key => {
            if (data[key] !== undefined && data[key] !== null) {
              this.settings[key] = data[key];
            }
          });
        }
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
    this.saveSuccess = false;
    this.saveError = '';

    this.api.updateSettings(this.settings).subscribe({
      next: (res: any) => {
        this.saving = false;
        if (res.status === 'ok') {
          this.saveSuccess = true;

          // Apply theme immediately
          document.documentElement.setAttribute('data-theme', this.settings.theme);

          setTimeout(() => {
            this.saveSuccess = false;
            this.cdr.detectChanges();
            window.location.reload();
          }, 1500);
        } else {
          this.saveError = res.message || 'Failed to save settings';
        }
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.saving = false;
        this.saveError = 'Network error — could not save settings';
        this.cdr.detectChanges();
      }
    });
  }

  toggleTheme() {
    this.settings.theme = this.settings.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', this.settings.theme);
    
    // Auto-save the theme so it persists without needing to click Save Settings
    this.api.updateSettings({ theme: this.settings.theme }).subscribe({
      error: (err: any) => console.error('Failed to auto-save theme', err)
    });
  }

  // ── File Upload ─────────────────────────────────────────────────────

  onDragOver(event: DragEvent) {
    event.preventDefault();
    this.dragOver = true;
  }

  onDragLeave() {
    this.dragOver = false;
  }

  onDrop(event: DragEvent) {
    event.preventDefault();
    this.dragOver = false;
    const files = event.dataTransfer?.files;
    if (files && files.length > 0) {
      this.processFile(files[0]);
    }
  }

  onFileSelect(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.processFile(input.files[0]);
    }
  }

  processFile(file: File) {
    if (!file.name.endsWith('.csv') && !file.name.endsWith('.txt')) {
      this.uploadResult = { status: 'error', message: 'Only .csv and .txt files are supported' };
      this.cdr.detectChanges();
      return;
    }

    this.uploading = true;
    this.uploadResult = null;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      this.api.uploadIocs(content).subscribe({
        next: (res: any) => {
          this.uploading = false;
          this.uploadResult = res;
          this.cdr.detectChanges();
        },
        error: () => {
          this.uploading = false;
          this.uploadResult = { status: 'error', message: 'Upload failed — network error' };
          this.cdr.detectChanges();
        }
      });
    };
    reader.readAsText(file);
  }

  getSeverityColor(level: string): string {
    switch (level) {
      case 'critical': return '#ff4444';
      case 'high':     return '#ff8800';
      case 'medium':   return '#ffcc00';
      case 'low':      return '#69f6b8';
      default:         return '#888888';
    }
  }
}
