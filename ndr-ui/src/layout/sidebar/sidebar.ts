import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { filter, Subscription } from 'rxjs';
import {
  LayoutDashboard, Bell, FileText, Activity, ShieldAlert, Search,
  Database, Settings, Network, Zap, Users, FolderSearch, Bot, Server,
  Building2, Gauge, KeyRound, Megaphone, ShieldCheck, Globe, ChevronDown, Map as MapIcon,
  LucideAngularModule
} from 'lucide-angular';
import { AuthService } from '../../services/auth/auth';

interface NavItem {
  label: string;
  route: string;
  icon: any;
  permission?: string;
  queryParams?: Record<string, string>;
}

interface NavGroup {
  section: string;
  collapsed: boolean;
  items: NavItem[];
}

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './sidebar.html',
  styleUrl: './sidebar.css',
})
export class Sidebar implements OnInit, OnDestroy {
  navGroups: NavGroup[] = [];
  ChevronDownIcon = ChevronDown;
  private navigationSub?: Subscription;

  constructor(private auth: AuthService, private router: Router) {}

  ngOnInit() {
    this.buildNavigation();
    this.navigationSub = this.router.events
      .pipe(filter(e => e instanceof NavigationEnd))
      .subscribe(() => this.buildNavigation());
  }

  ngOnDestroy() { this.navigationSub?.unsubscribe(); }

  toggleGroup(group: NavGroup) { group.collapsed = !group.collapsed; }

  isActive(item: NavItem): boolean {
    if (item.queryParams) {
      const tree = this.router.createUrlTree([item.route], { queryParams: item.queryParams });
      return this.router.isActive(tree, { paths: 'exact', queryParams: 'exact', fragment: 'ignored', matrixParams: 'ignored' });
    }
    return this.router.isActive(item.route, { paths: 'exact', queryParams: 'ignored', fragment: 'ignored', matrixParams: 'ignored' });
  }

  private buildNavigation() {
    // Preserve collapsed state across navigation rebuilds
    const collapsed = new Map<string, boolean>();
    this.navGroups.forEach(g => collapsed.set(g.section, g.collapsed));

    const user = this.auth.getUser();
    const isDefaultTenant = user?.tenant_id === 'default';

    if (this.auth.isAdmin()) {
      this.navGroups = [
        { section: 'MANAGEMENT', collapsed: false, items: [
          { label: 'Overview',  route: '/admin', queryParams: { tab: 'overview' }, icon: LayoutDashboard },
          { label: 'Tenants',   route: '/admin', queryParams: { tab: 'tenants' }, icon: Building2 },
          { label: 'Users',     route: '/admin', queryParams: { tab: 'users' },   icon: Users },
        ]},
        { section: 'INFRASTRUCTURE', collapsed: false, items: [
          { label: 'Engines', route: '/admin', queryParams: { tab: 'engines' }, icon: Gauge },
          { label: 'Sensors', route: '/admin', queryParams: { tab: 'sensors' }, icon: KeyRound },
          { label: 'Rules',   route: '/rules',                                  icon: ShieldAlert },
        ]},
        { section: 'MONITORING', collapsed: false, items: [
          { label: 'Announcements',  route: '/admin', queryParams: { tab: 'announcements' },   icon: Megaphone },
          { label: 'Telemetry',      route: '/admin', queryParams: { tab: 'telemetry' },       icon: Activity },
          { label: 'Trusted Cloud',  route: '/admin', queryParams: { tab: 'trusted-cloud' },   icon: ShieldCheck },
          { label: 'Trusted Domains',route: '/admin', queryParams: { tab: 'trusted-domains' }, icon: Globe },
        ]},
        { section: 'INTEGRATIONS', collapsed: false, items: [
          { label: 'AI Providers', route: '/admin', queryParams: { tab: 'ai-providers' }, icon: Bot },
          { label: 'SMTP Config',  route: '/admin', queryParams: { tab: 'smtp-config' }, icon: Settings },
        ]},
      ];

    } else if (user?.role === 'tenant_admin') {
      this.navGroups = [
        { section: 'ADMIN', collapsed: false, items: [
          { label: 'Tenant Admin', route: '/tenant-admin', icon: Users },
        ]},
      ];

    } else {
      const has = (p: string) => this.auth.hasPermission(p);

      const overviewItems: NavItem[] = [];
      if (has('dashboard')) overviewItems.push({ label: 'Dashboard', route: '/analyst/dashboard', icon: LayoutDashboard, permission: 'dashboard' });

      const threatItems: NavItem[] = [];
      if (has('alerts')) threatItems.push({ label: 'Alerts',       route: '/analyst/alerts',      icon: Bell,   permission: 'alerts' });
      if (has('intel'))  threatItems.push({ label: 'Threat Intel', route: '/analyst/intel',        icon: Search, permission: 'intel'  });
      if (has('intel'))  threatItems.push({ label: 'Attack Map',   route: '/analyst/threat-map',   icon: MapIcon, permission: 'intel'  });

      const networkItems: NavItem[] = [];
      if (has('logs'))        networkItems.push({ label: 'Network',     route: '/analyst/logs',        icon: FileText, permission: 'logs'        });
      if (has('network-map')) networkItems.push({ label: 'Network Map', route: '/analyst/network-map', icon: Network,  permission: 'network-map' });
      if (has('assets'))      networkItems.push({ label: 'Assets',      route: '/analyst/assets',      icon: Server,   permission: 'assets'      });

      const enforceItems: NavItem[] = [];
      if (has('rules')) enforceItems.push({ label: 'Rules', route: '/analyst/rules', icon: ShieldAlert, permission: 'rules' });

      const systemItems: NavItem[] = [];
      if (has('health')) systemItems.push({ label: 'System Health', route: '/analyst/health', icon: Database, permission: 'health' });
      if (isDefaultTenant && has('setup')) systemItems.push({ label: 'Sensor Setup', route: '/analyst/setup', icon: Settings, permission: 'setup' });

      const responseItems: NavItem[] = [];
      if (has('soar'))     responseItems.push({ label: 'SOAR',     route: '/analyst/soar',     icon: Zap,         permission: 'soar'     });
      if (has('evidence')) responseItems.push({ label: 'Evidence', route: '/analyst/evidence', icon: FolderSearch, permission: 'evidence' });

      const intelItems: NavItem[] = [];
      if (has('ai-activity') && this.auth.isTenantAiEnabled())
        intelItems.push({ label: 'AI Activity', route: '/analyst/ai-activity', icon: Bot, permission: 'ai-activity' });

      this.navGroups = [
        ...(overviewItems.length  ? [{ section: 'OVERVIEW',  collapsed: false, items: overviewItems  }] : []),
        ...(threatItems.length    ? [{ section: 'THREATS',   collapsed: false, items: threatItems    }] : []),
        ...(networkItems.length   ? [{ section: 'NETWORK',   collapsed: false, items: networkItems   }] : []),
        ...(enforceItems.length   ? [{ section: 'ENFORCE',   collapsed: false, items: enforceItems   }] : []),
        ...(systemItems.length    ? [{ section: 'SYSTEM',    collapsed: false, items: systemItems    }] : []),
        ...(responseItems.length  ? [{ section: 'RESPONSE',  collapsed: false, items: responseItems  }] : []),
        ...(intelItems.length     ? [{ section: 'INTEL',     collapsed: false, items: intelItems     }] : []),
      ];
    }

    // Restore any previously collapsed groups so navigation doesn't reset them
    this.navGroups.forEach(g => {
      if (collapsed.has(g.section)) g.collapsed = collapsed.get(g.section)!;
    });
  }
}
