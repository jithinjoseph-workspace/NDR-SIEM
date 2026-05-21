import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { Api } from '../../services/api/api';
import { Websocket } from '../../services/websocket/websocket';
import { AuthService } from '../../services/auth/auth';
import { Subscription } from 'rxjs';
import { filter } from 'rxjs/operators';
import { LucideAngularModule, Settings, Play, Square, RefreshCcw, ShieldCheck, Activity } from 'lucide-angular';

@Component({
  selector: 'app-setup',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './setup.html',
  styleUrl: './setup.css'
})
export class Setup implements OnInit, OnDestroy {
  interfaces: string[] = [];
  selectedInterface: string = '';
  status: 'Ready' | 'Starting...' | 'Running' | 'Stopping...' | 'Stopped' = 'Ready';
  zeekStatus: string = 'stopped';
  suricataStatus: string = 'stopped';
  vectorStatus: string = 'stopped';

  private subs: Subscription[] = [];

  SettingsIcon = Settings;
  PlayIcon = Play;
  StopIcon = Square;
  RefreshIcon = RefreshCcw;
  ShieldIcon = ShieldCheck;
  ActivityIcon = Activity;

  constructor(
    private api: Api,
    private ws: Websocket,
    private cdr: ChangeDetectorRef,
    private auth: AuthService,
    private router: Router
  ) {}

  ngOnInit() {
    const user = this.auth.getUser();
    if (user?.tenant_id !== 'default') {
      this.router.navigate(['/dashboard']);
      return;
    }

    // HTTP on load — interfaces
    this.api.getInterfaces().subscribe(data => {
      this.interfaces = data || [];
      this.cdr.detectChanges();  // force render for interfaces
    });

    // HTTP on load — agent status
    this.api.getAgentStatus().subscribe(data => {
      if (data) {
        this.updateStatus(data);
        this.cdr.detectChanges();
      }
    });

    // WebSocket — real-time updates
    this.subs.push(
      this.ws.lastAgentStatus$.pipe(
        filter(d => d !== null)
      ).subscribe(data => {
        this.updateStatus(data);
        this.cdr.detectChanges();
      })
    );
  }

  updateStatus(data: any) {
    this.zeekStatus = data.zeek || 'stopped';
    this.suricataStatus = data.suricata || 'stopped';
    this.vectorStatus = data.vector || 'stopped';
    this.selectedInterface = data.interface || this.selectedInterface;

    if (data.zeek === 'running' || data.suricata === 'running' || data.vector === 'running') {
      this.status = 'Running';
    } else if (this.status !== 'Starting...' && this.status !== 'Stopping...') {
      this.status = 'Stopped';
    }
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }

  applyInterface() {
    this.api.setInterface(this.selectedInterface).subscribe(() => {
      console.log('Interface set to', this.selectedInterface);
    });
  }

  startMonitoring() {
    this.status = 'Starting...';
    this.api.startServices().subscribe({
      next: () => {},
      error: () => { this.status = 'Stopped'; }
    });
  }

  stopMonitoring() {
    this.status = 'Stopping...';
    this.api.stopServices().subscribe({
      next: () => {},
      error: () => { this.status = 'Running'; }
    });
  }
}