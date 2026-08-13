import { Component, OnInit, signal, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import {
  LucideAngularModule,
  LayoutDashboard, Building2, Users, Server, KeyRound,
  Megaphone, Activity, Zap, Cloud, Globe, Mail, ShieldCheck,
  ChevronDown, Gavel, HelpCircle,
} from 'lucide-angular';
import { AuthService } from '../../services/auth/auth';

@Component({
  selector: 'app-admin-layout',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './admin-layout.html',
  styleUrl: './admin-layout.css',
})
export class AdminLayout implements OnInit {
  OverviewIcon      = LayoutDashboard;
  TenantsIcon       = Building2;
  UsersIcon         = Users;
  EnginesIcon       = Server;
  SensorsIcon       = KeyRound;
  AnnouncementsIcon = Megaphone;
  TelemetryIcon     = Activity;
  AiIcon            = Zap;
  CloudIcon         = Cloud;
  DomainsIcon       = Globe;
  SmtpIcon          = Mail;
  ShieldIcon        = ShieldCheck;
  ChevronIcon       = ChevronDown;
  RulesIcon         = Gavel;
  SupportIcon       = HelpCircle;

  groups: Record<string, boolean> = {
    access:         true,
    infrastructure: true,
    monitoring:     true,
    config:         true,
  };

  currentUser = signal<any>(null);

  constructor(private auth: AuthService, private router: Router) {}

  ngOnInit() {
    this.currentUser.set(this.auth.getUser());
    const url = this.router.url;
    this.groups = {
      access:         url.includes('/tenants') || url.includes('/users'),
      infrastructure: url.includes('/engines') || url.includes('/sensors'),
      monitoring:     url.includes('/rules') || url.includes('/telemetry') || url.includes('/announcements'),
      config:         url.includes('/ai-providers') || url.includes('/trusted-cloud')
                      || url.includes('/trusted-domains') || url.includes('/smtp-config'),
    };
    if (!Object.values(this.groups).some(v => v)) {
      Object.keys(this.groups).forEach(k => this.groups[k] = true);
    }
  }

  toggleGroup(key: string) {
    this.groups[key] = !this.groups[key];
  }
}
