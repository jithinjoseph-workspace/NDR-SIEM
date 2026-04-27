import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { 
    path: 'dashboard', 
    loadComponent: () => import('../pages/dashboard/dashboard').then(m => m.Dashboard) 
  },
  { 
    path: 'alerts', 
    loadComponent: () => import('../pages/alerts/alerts').then(m => m.Alerts) 
  },
  { 
    path: 'logs', 
    loadComponent: () => import('../pages/logs/logs').then(m => m.Logs) 
  },
  { 
    path: 'live', 
    loadComponent: () => import('../pages/live/live').then(m => m.Live) 
  },
  { 
    path: 'rules', 
    loadComponent: () => import('../pages/rules/rules').then(m => m.Rules) 
  },
  { 
    path: 'intel', 
    loadComponent: () => import('../pages/intel/intel').then(m => m.Intel) 
  },
  { 
    path: 'health', 
    loadComponent: () => import('../pages/health/health').then(m => m.Health) 
  },
  { 
    path: 'setup', 
    loadComponent: () => import('../pages/setup/setup').then(m => m.Setup) 
  },
  { 
    path: 'network-map', 
    loadComponent: () => import('../pages/network-map/network-map').then(m => m.NetworkMap) 
  },

  { path: '**', redirectTo: 'dashboard' }
];
