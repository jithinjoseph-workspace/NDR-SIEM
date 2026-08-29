import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { filter, Subscription } from 'rxjs';
import {
  LayoutDashboard, Bell, FileText, ShieldAlert, Search,
  Database, Settings, Network, Zap, FolderSearch, Bot, Server,
  ChevronDown, Map as MapIcon, Shield, RotateCcw,
  Radio, BarChart2, ScrollText,
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
 
    const has = (p: string) => this.auth.hasPermission(p);

    const hasNdr = this.auth.hasFeature('ndr');

    const overviewItems: NavItem[] = [];
    // Dashboard is universal — shows NDR section, SIEM section, or both depending on product mode
    if (has('dashboard') || has('siem-dashboard') || this.auth.hasFeature('siem')) overviewItems.push({ label: 'Dashboard', route: '/analyst/dashboard', icon: LayoutDashboard, permission: 'dashboard' });

    const threatItems: NavItem[] = [];
    if (hasNdr && has('alerts')) threatItems.push({ label: 'Alerts',       route: '/analyst/alerts',     icon: Bell,    permission: 'alerts' });
    if (hasNdr && has('intel'))  threatItems.push({ label: 'Threat Intel', route: '/analyst/intel',       icon: Search,  permission: 'intel'  });
    if (hasNdr && has('intel'))  threatItems.push({ label: 'Attack Map',   route: '/analyst/threat-map',  icon: MapIcon, permission: 'intel'  });

    const networkItems: NavItem[] = [];
    if (hasNdr && has('logs'))        networkItems.push({ label: 'Network',     route: '/analyst/logs',        icon: FileText, permission: 'logs'        });
    if (hasNdr && has('network-map')) networkItems.push({ label: 'Network Map', route: '/analyst/network-map', icon: Network,  permission: 'network-map' });
    if (hasNdr && has('assets'))      networkItems.push({ label: 'Assets',      route: '/analyst/assets',      icon: Server,   permission: 'assets'      });

    const enforceItems: NavItem[] = [];
    if (hasNdr && has('rules'))       enforceItems.push({ label: 'Rules',         route: '/analyst/rules',         icon: ShieldAlert, permission: 'rules'  });
    if (hasNdr && has('retrospective')) enforceItems.push({ label: 'Retrospective', route: '/analyst/retrospective', icon: RotateCcw,   permission: 'retrospective' });
    if (hasNdr && has('honeypots'))   enforceItems.push({ label: 'Honeypots',     route: '/analyst/honeypots',     icon: Shield,      permission: 'honeypots' });

    const systemItems: NavItem[] = [];
    if (hasNdr && has('health')) systemItems.push({ label: 'System Health', route: '/analyst/health', icon: Database, permission: 'health' });
    if (hasNdr && isDefaultTenant && has('setup')) systemItems.push({ label: 'Sensor Setup', route: '/analyst/setup', icon: Settings, permission: 'setup' });

    const responseItems: NavItem[] = [];
    if (hasNdr && has('soar') && this.auth.hasFeature('soar'))
      responseItems.push({ label: 'SOAR', route: '/analyst/soar', icon: Zap, permission: 'soar' });
    if (hasNdr && has('evidence')) responseItems.push({ label: 'Evidence', route: '/analyst/evidence', icon: FolderSearch, permission: 'evidence' });

    const intelItems: NavItem[] = [];
    if (hasNdr && has('ai-activity') && this.auth.isTenantAiEnabled())
      intelItems.push({ label: 'AI Activity', route: '/analyst/ai-activity', icon: Bot, permission: 'ai-activity' });

    // SIEM section — Sources managed in tenant-admin; nothing analyst-visible here
    const siemItems: NavItem[] = [];

    // XDR unified alerts — visible to any tenant with NDR or SIEM
    const xdrItems: NavItem[] = [];
    if (has('alerts')) {
      xdrItems.push({ label: 'Unified Alerts', route: '/xdr/alerts', icon: Bell, permission: 'alerts' });
    }

    this.navGroups = [
      ...(overviewItems.length  ? [{ section: 'OVERVIEW',  collapsed: false, items: overviewItems  }] : []),
      ...(threatItems.length    ? [{ section: 'THREATS',   collapsed: false, items: threatItems    }] : []),
      ...(networkItems.length   ? [{ section: 'NETWORK',   collapsed: false, items: networkItems   }] : []),
      ...(enforceItems.length   ? [{ section: 'ENFORCE',   collapsed: false, items: enforceItems   }] : []),
      ...(systemItems.length    ? [{ section: 'SYSTEM',    collapsed: false, items: systemItems    }] : []),
      ...(responseItems.length  ? [{ section: 'RESPONSE',  collapsed: false, items: responseItems  }] : []),
      ...(intelItems.length     ? [{ section: 'INTEL',     collapsed: false, items: intelItems     }] : []),
      ...(siemItems.length      ? [{ section: 'SIEM',      collapsed: false, items: siemItems      }] : []),
      ...(xdrItems.length       ? [{ section: 'XDR',       collapsed: false, items: xdrItems       }] : []),
    ];

    // Restore any previously collapsed groups so navigation doesn't reset them
    this.navGroups.forEach(g => {
      if (collapsed.has(g.section)) g.collapsed = collapsed.get(g.section)!;
    });
  }
}
