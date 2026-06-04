import { Routes } from '@angular/router';
import { authGuard } from '../services/auth/auth-guard';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  {
    path: 'login',
    loadComponent: () => import('../pages/login/login')
      .then(m => m.Login)
  },
  {
    path: 'dashboard',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'dashboard' },
    loadComponent: () => import('../pages/dashboard/dashboard')
      .then(m => m.Dashboard)
  },
  {
    path: 'alerts',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'alerts' },
    loadComponent: () => import('../pages/alerts/alerts')
      .then(m => m.Alerts)
  },
  {
    path: 'logs',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'logs' },
    loadComponent: () => import('../pages/logs/logs')
      .then(m => m.Logs)
  },
  {
    path: 'live',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'live' },
    loadComponent: () => import('../pages/live/live')
      .then(m => m.Live)
  },
  {
    path: 'rules',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'rules' },
    loadComponent: () => import('../pages/rules/rules')
      .then(m => m.Rules)
  },
  {
    path: 'intel',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'intel' },
    loadComponent: () => import('../pages/intel/intel')
      .then(m => m.Intel)
  },
  {
    path: 'health',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'health' },
    loadComponent: () => import('../pages/health/health')
      .then(m => m.Health)
  },
  {
    path: 'setup',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'setup' },
    loadComponent: () => import('../pages/setup/setup')
      .then(m => m.Setup)
  },
  {
    path: 'network-map',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'network-map' },
    loadComponent: () => import('../pages/network-map/network-map')
      .then(m => m.NetworkMap)
  },
  {
    path: 'soar',
    canActivate: [authGuard],
    data: { role: 'analyst', permission: 'soar' },
    loadComponent: () => import('../pages/soar/soar')
      .then(m => m.Soar)
  },
  {
    path: 'settings',
    canActivate: [authGuard],
    loadComponent: () => import('../pages/settings/settings')
      .then(m => m.Settings)
  },
  {
    path: 'admin',
    canActivate: [authGuard],
    data: { role: 'admin' },
    loadComponent: () => import('../pages/admin/admin')
      .then(m => m.Admin)
  },
  {
    path: 'tenant-admin',
    canActivate: [authGuard],
    loadComponent: () => import('../pages/tenant-admin/tenant-admin')
      .then(m => m.TenantAdmin)
  },
  {
    path: 'support',
    canActivate: [authGuard],
    loadComponent: () => import('../pages/support/support')
      .then(m => m.Support)
  },
  { path: '**', redirectTo: 'login' }
];
