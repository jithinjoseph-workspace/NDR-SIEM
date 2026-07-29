import { Component, OnInit, OnDestroy, ChangeDetectorRef, ViewEncapsulation, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  LucideAngularModule,
  Activity, Building2, Users, Server,
  ShieldCheck, Zap, TrendingUp, Clock,
} from 'lucide-angular';
import * as d3 from 'd3';
import { Api } from '../../../services/api/api';

@Component({
  selector: 'app-overview',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.Default,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './overview.html',
  styleUrl: './overview.css',
})
export class Overview implements OnInit, OnDestroy {
  ActivityIcon  = Activity;
  BuildingIcon  = Building2;
  UsersIcon     = Users;
  ServerIcon    = Server;
  ShieldIcon    = ShieldCheck;
  ZapIcon       = Zap;
  TrendIcon     = TrendingUp;
  ClockIcon     = Clock;

  users: any[]    = [];
  tenants: any[]  = [];
  engines: any[]  = [];

  currentTime = '';
  currentDate = '';
  private clockTimer: any = null;

  overviewTelemetryHistory: { time: Date; cpu: number; mem: number }[] = [];
  private overviewTelemetryPollTimer: any = null;
  private resizeObserver: any = null;
  private resizeTimeout: any = null;

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  get activeEngines()  { return this.engines.filter(e => e.status?.toLowerCase().includes('up') || e.status?.toLowerCase().includes('health')).length; }
  get activeTenantsCount() { return this.tenants.filter(t => t.active).length; }

  private updateClock() {
    const now = new Date();
    this.currentTime = now.toLocaleTimeString('en-US', { hour12: false });
    this.currentDate = now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
    this.cdr.detectChanges();
  }

  ngOnInit() {
    this.updateClock();
    this.clockTimer = setInterval(() => this.updateClock(), 1000);
    this.api.getUsers().subscribe({
      next: (data: any) => {
        this.users = data.users || [];
        this.cdr.detectChanges();
        this.renderD3Charts();
      },
      error: () => {},
    });
    this.api.getTenants().subscribe({
      next: (data: any) => {
        this.tenants = data.tenants || [];
        this.cdr.detectChanges();
        this.renderD3Charts();
      },
      error: () => {},
    });
    this.api.getEngines().subscribe({
      next: (data: any) => {
        this.engines = data.engines || [];
        this.cdr.detectChanges();
        this.renderD3Charts();
      },
      error: () => {},
    });

    setTimeout(() => {
      this.renderD3Charts();
      this.setupResizeObserver();
      this.startOverviewTelemetryPolling();
    }, 150);
  }

  ngOnDestroy() {
    if (this.clockTimer) clearInterval(this.clockTimer);
    this.stopOverviewTelemetryPolling();
    if (this.resizeObserver) this.resizeObserver.disconnect();
  }

  get activeTenants() { return this.tenants.filter(t => t.active).length; }
  get managedUsers()  { return this.users.filter(u => u.role !== 'super_admin'); }

  private setupResizeObserver() {
    const grid = document.querySelector('.overview-grid');
    if (grid && !this.resizeObserver) {
      this.resizeObserver = new ResizeObserver(() => {
        if (this.resizeTimeout) clearTimeout(this.resizeTimeout);
        this.resizeTimeout = setTimeout(() => this.renderD3Charts(), 100);
      });
      this.resizeObserver.observe(grid);
    }
  }

  startOverviewTelemetryPolling() {
    if (this.overviewTelemetryPollTimer) return;
    this.pollOverviewTelemetry();
    this.overviewTelemetryPollTimer = setInterval(() => this.pollOverviewTelemetry(), 3000);
  }

  stopOverviewTelemetryPolling() {
    if (this.overviewTelemetryPollTimer) {
      clearInterval(this.overviewTelemetryPollTimer);
      this.overviewTelemetryPollTimer = null;
    }
  }

  pollOverviewTelemetry() {
    this.api.getPlatformTelemetry().subscribe({
      next: (data: any) => {
        this.overviewTelemetryHistory.push({
          time: new Date(),
          cpu: data.cpu_usage_percent || 0,
          mem: data.memory_percent || 0,
        });
        if (this.overviewTelemetryHistory.length > 20) this.overviewTelemetryHistory.shift();
        this.renderResourceUtilizationArea();
      },
    });
  }

  renderD3Charts() {
    this.renderResourceUtilizationArea();
    this.renderUserRolesDonut();
    this.renderTopTenantsBar();
    this.renderProcessingEnginesDonut();
  }

  private addGlowFilter(defs: any, id: string, color: string, blur = 3) {
    const f = defs.append('filter').attr('id', id)
      .attr('x', '-60%').attr('y', '-60%').attr('width', '220%').attr('height', '220%');
    f.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', blur).attr('result', 'blur');
    f.append('feFlood').attr('flood-color', color).attr('flood-opacity', 0.6).attr('result', 'color');
    f.append('feComposite').attr('in', 'color').attr('in2', 'blur').attr('operator', 'in').attr('result', 'glow');
    const merge = f.append('feMerge');
    merge.append('feMergeNode').attr('in', 'glow');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');
  }

  private getOrCreateTooltip(): any {
    let tt: any = d3.select('body').select('.d3-tooltip');
    if (tt.empty()) tt = d3.select('body').append('div').attr('class', 'd3-tooltip').style('opacity', 0);
    return tt;
  }

  renderResourceUtilizationArea() {
    const container = d3.select('#resource-area-chart');
    container.selectAll('*').remove();
    if (container.empty()) return;

    const containerNode = container.node() as HTMLElement;
    const width = containerNode.clientWidth || 800;
    const height = 300;
    const margin = { top: 20, right: 20, bottom: 32, left: 48 };
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    const svgRoot = container.append('svg')
      .attr('width', '100%').attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('preserveAspectRatio', 'xMidYMid meet');

    const defs = svgRoot.append('defs');
    this.addGlowFilter(defs, 'ov-glow-cyan', '#22d3ee', 4);
    this.addGlowFilter(defs, 'ov-glow-violet', '#a78bfa', 4);

    const gradCpu = defs.append('linearGradient').attr('id', 'ov-cpu-grad').attr('x1', '0%').attr('y1', '0%').attr('x2', '0%').attr('y2', '100%');
    gradCpu.append('stop').attr('offset', '0%').attr('stop-color', 'rgba(34,211,238,0.20)');
    gradCpu.append('stop').attr('offset', '100%').attr('stop-color', 'rgba(34,211,238,0.00)');

    const gradMem = defs.append('linearGradient').attr('id', 'ov-mem-grad').attr('x1', '0%').attr('y1', '0%').attr('x2', '0%').attr('y2', '100%');
    gradMem.append('stop').attr('offset', '0%').attr('stop-color', 'rgba(167,139,250,0.16)');
    gradMem.append('stop').attr('offset', '100%').attr('stop-color', 'rgba(167,139,250,0.00)');

    const svg = svgRoot.append('g').attr('transform', `translate(${margin.left},${margin.top})`);
    const data = this.overviewTelemetryHistory.length > 0
      ? this.overviewTelemetryHistory
      : [{ time: new Date(Date.now() - 3000), cpu: 0, mem: 0 }, { time: new Date(), cpu: 0, mem: 0 }];

    const x = d3.scaleTime().domain(d3.extent(data, (d: any) => d.time) as [Date, Date]).range([0, innerW]);
    const y = d3.scaleLinear().domain([0, 100]).range([innerH, 0]);

    svg.append('g').attr('class', 'chart-grid')
      .call(d3.axisLeft(y).tickSize(-innerW).tickFormat(() => '').ticks(5));
    svg.append('g').attr('class', 'chart-axis').attr('transform', `translate(0,${innerH})`)
      .call(d3.axisBottom(x).ticks(4).tickSizeOuter(0).tickFormat((d: any) => d3.timeFormat('%H:%M')(d)));
    svg.append('g').attr('class', 'chart-axis')
      .call(d3.axisLeft(y).ticks(5).tickSizeOuter(0).tickFormat((d: any) => `${d}%`));

    const cpuArea = d3.area<any>().x(d => x(d.time)).y0(innerH).y1(d => y(d.cpu)).curve(d3.curveMonotoneX);
    const memArea = d3.area<any>().x(d => x(d.time)).y0(innerH).y1(d => y(d.mem)).curve(d3.curveMonotoneX);
    const cpuLine = d3.line<any>().x(d => x(d.time)).y(d => y(d.cpu)).curve(d3.curveMonotoneX);
    const memLine = d3.line<any>().x(d => x(d.time)).y(d => y(d.mem)).curve(d3.curveMonotoneX);

    // Draw memory fill first (larger), then CPU fill on top
    svg.append('path').datum(data).attr('fill', 'url(#ov-mem-grad)').attr('d', memArea);
    svg.append('path').datum(data).attr('fill', 'url(#ov-cpu-grad)').attr('d', cpuArea);

    // Glowing lines — memory behind, CPU on top
    svg.append('path').datum(data).attr('fill', 'none')
      .attr('stroke', '#a78bfa').attr('stroke-width', 2)
      .attr('filter', 'url(#ov-glow-violet)').attr('d', memLine);
    svg.append('path').datum(data).attr('fill', 'none')
      .attr('stroke', '#22d3ee').attr('stroke-width', 2.5)
      .attr('filter', 'url(#ov-glow-cyan)').attr('d', cpuLine);

    // Live endpoint dots
    if (data.length > 1) {
      const last = data[data.length - 1];
      svg.append('circle').attr('cx', x(last.time)).attr('cy', y(last.mem))
        .attr('r', 4).attr('fill', '#a78bfa').attr('stroke', 'rgba(8,12,26,0.9)').attr('stroke-width', 1.5)
        .attr('filter', 'url(#ov-glow-violet)');
      svg.append('circle').attr('cx', x(last.time)).attr('cy', y(last.cpu))
        .attr('r', 5).attr('fill', '#22d3ee').attr('stroke', 'rgba(8,12,26,0.9)').attr('stroke-width', 2)
        .attr('filter', 'url(#ov-glow-cyan)');
    }
  }

  private renderDonut(
    containerId: string,
    data: { label: string; value: number }[],
    colors: string[],
    centerNum: number | string,
    centerLabel: string,
    tooltip: any,
    tooltipFn: (d: any) => string,
  ) {
    const container = d3.select(containerId);
    container.selectAll('*').remove();
    if (container.empty()) return;

    const containerNode = container.node() as HTMLElement;
    const width = containerNode.clientWidth || 300;
    const height = 280;
    const radius = Math.min(width, height) / 2 - 16;

    const svgRoot = container.append('svg').attr('width', '100%').attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`).attr('preserveAspectRatio', 'xMidYMid meet');

    const defs = svgRoot.append('defs');
    this.addGlowFilter(defs, `${containerId.replace('#', '')}-glow`, colors[0], 5);

    const svg = svgRoot.append('g').attr('transform', `translate(${width / 2},${height / 2})`);

    const color = d3.scaleOrdinal<string>().domain(data.map(d => d.label)).range(colors);
    const pie = d3.pie<any>().value(d => d.value).sort(null).padAngle(0.035);
    const arc = d3.arc<any>().innerRadius(radius * 0.62).outerRadius(radius);
    const hoverArc = d3.arc<any>().innerRadius(radius * 0.62).outerRadius(radius + 8).padAngle(0.035);

    const arcs = svg.selectAll('path').data(pie(data)).enter().append('path')
      .attr('fill', (d: any) => color(d.data.label))
      .style('stroke', 'none')
      .attr('d', (d: any) => {
        const start = { ...d, endAngle: d.startAngle };
        return arc(start);
      })
      .on('mouseover', function(event: any, d: any) {
        d3.select(this).transition().duration(180).attr('d', hoverArc);
        tooltip.transition().duration(40).style('opacity', 1);
        tooltip.html(tooltipFn(d))
          .style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
      })
      .on('mousemove', function(event: any) {
        tooltip.style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
      })
      .on('mouseout', function() {
        d3.select(this).transition().duration(180).attr('d', arc);
        tooltip.transition().duration(200).style('opacity', 0);
      });

    // Animate entrance
    arcs.transition().duration(650).ease(d3.easeCubicOut)
      .attrTween('d', function(d: any) {
        const interp = d3.interpolate({ ...d, endAngle: d.startAngle }, d);
        return (t: number) => arc(interp(t)) || '';
      });

    // Inner ring
    svg.append('circle').attr('r', radius * 0.62 - 1).attr('fill', 'none')
      .attr('stroke', 'rgba(79,140,255,0.08)').attr('stroke-width', 1);

    // Center text
    svg.append('text').attr('text-anchor', 'middle').attr('dy', '-0.15em')
      .attr('fill', '#e8f0ff').style('font-size', '26px').style('font-weight', '700')
      .style('font-variant-numeric', 'tabular-nums').style('font-family', 'monospace')
      .text(centerNum);
    svg.append('text').attr('text-anchor', 'middle').attr('dy', '1.3em')
      .attr('fill', '#3A5070').style('font-size', '10.5px').style('letter-spacing', '0.08em')
      .style('text-transform', 'uppercase').text(centerLabel);
  }

  renderUserRolesDonut() {
    const roles: any = { 'Platform Admin': 0, 'Tenant Admin': 0, 'Analyst': 0, 'Viewer': 0, 'Other': 0 };
    for (const u of this.users) {
      if (u.role === 'admin' || u.role === 'super_admin') roles['Platform Admin']++;
      else if (u.role === 'tenant_admin') roles['Tenant Admin']++;
      else if (u.role === 'analyst' || u.role === 'senior_analyst') roles['Analyst']++;
      else if (u.role === 'viewer') roles['Viewer']++;
      else roles['Other']++;
    }
    let data: any[] = Object.entries(roles).filter(([, v]: [string, any]) => v > 0).map(([label, value]) => ({ label, value }));
    if (data.length === 0) data = [{ label: 'No Users', value: 1 }];
    const total = d3.sum(data, (d: any) => d.label === 'No Users' ? 0 : Number(d.value));
    this.renderDonut(
      '#user-roles-donut-chart', data,
      ['#22d3ee', '#a78bfa', '#4ade80', '#fbbf24', '#64748b'],
      total, 'Total Users',
      this.getOrCreateTooltip(),
      (d: any) => `<strong>${d.data.label}</strong><br/>Users: ${d.data.value}`,
    );
  }

  renderTopTenantsBar() {
    const container = d3.select('#tenant-bar-chart');
    container.selectAll('*').remove();
    if (container.empty()) return;

    const tenantUserCounts: any = {};
    for (const t of this.tenants) tenantUserCounts[t.id] = { name: t.name, count: 0 };
    for (const u of this.users) {
      if (u.tenant_id && tenantUserCounts[u.tenant_id]) tenantUserCounts[u.tenant_id].count++;
    }
    let data: { name: string; count: number }[] = (Object.values(tenantUserCounts) as any[])
      .filter((t: any) => t.count > 0).sort((a: any, b: any) => b.count - a.count).slice(0, 5);
    if (data.length === 0) data = [{ name: 'No Data', count: 0 }];

    const containerNode = container.node() as HTMLElement;
    const width = containerNode.clientWidth || 400;
    const height = 280;
    const margin = { top: 16, right: 48, bottom: 36, left: 100 };
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    const svgRoot = container.append('svg').attr('width', '100%').attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`).attr('preserveAspectRatio', 'xMidYMid meet');

    const defs = svgRoot.append('defs');
    // Per-bar gradient: violet → cyan
    data.forEach((_, i) => {
      const g = defs.append('linearGradient').attr('id', `ov-bar-grad-${i}`)
        .attr('x1', '0%').attr('y1', '0%').attr('x2', '100%').attr('y2', '0%');
      g.append('stop').attr('offset', '0%').attr('stop-color', '#7c3aed');
      g.append('stop').attr('offset', '100%').attr('stop-color', '#22d3ee');
    });

    const svg = svgRoot.append('g').attr('transform', `translate(${margin.left},${margin.top})`);
    const x = d3.scaleLinear().domain([0, d3.max(data, d => d.count) || 1]).nice().range([0, innerW]);
    const y = d3.scaleBand().domain(data.map(d => d.name)).range([0, innerH]).padding(0.35);

    svg.append('g').attr('class', 'chart-grid')
      .call(d3.axisLeft(y).tickSize(-innerW).tickFormat(() => '').ticks(data.length));
    svg.append('g').attr('class', 'chart-axis').attr('transform', `translate(0,${innerH})`)
      .call(d3.axisBottom(x).ticks(Math.min(5, d3.max(data, d => d.count) || 1)).tickSizeOuter(0));
    svg.append('g').attr('class', 'chart-axis')
      .call(d3.axisLeft(y).tickSizeOuter(0));

    const tooltip = this.getOrCreateTooltip();

    const bars = svg.selectAll('.bar').data(data).enter().append('rect').attr('class', 'bar')
      .attr('x', 0).attr('y', d => y(d.name)!).attr('height', y.bandwidth())
      .attr('width', 0).attr('fill', (_, i) => `url(#ov-bar-grad-${i})`).attr('rx', 4)
      .on('mouseover', function(event: any, d: any) {
        d3.select(this).style('opacity', 1);
        tooltip.transition().duration(40).style('opacity', 1);
        tooltip.html(`<strong>${d.name}</strong><br/>Users: ${d.count}`)
          .style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
      })
      .on('mousemove', function(event: any) {
        tooltip.style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 28) + 'px');
      })
      .on('mouseout', function() {
        d3.select(this).style('opacity', 0.9);
        tooltip.transition().duration(200).style('opacity', 0);
      });

    bars.transition().duration(650).ease(d3.easeQuadOut)
      .attr('width', d => x(d.count));

    // Value labels — appear after bar animates
    svg.selectAll('.bar-label').data(data).enter().append('text').attr('class', 'bar-label')
      .attr('x', d => x(d.count) + 6).attr('y', d => y(d.name)! + y.bandwidth() / 2)
      .attr('dy', '0.35em').attr('fill', '#4F7090').style('font-size', '11px')
      .style('font-family', 'monospace').text(d => d.count)
      .style('opacity', 0).transition().delay(600).duration(200).style('opacity', 1);
  }

  renderProcessingEnginesDonut() {
    let up = 0, offline = 0;
    for (const e of this.engines) {
      if (e.status && (e.status.toLowerCase().includes('up') || e.status.toLowerCase().includes('running'))) up++;
      else offline++;
    }
    let data: any[] = [{ label: 'Running', value: up }, { label: 'Offline', value: offline }].filter(d => d.value > 0);
    if (data.length === 0) data = [{ label: 'No Engines', value: 1 }];
    const total = d3.sum(data, (d: any) => d.label === 'No Engines' ? 0 : Number(d.value));
    this.renderDonut(
      '#engines-donut-chart', data,
      ['#4ade80', '#ef4444', '#64748b'],
      total, 'Total Nodes',
      this.getOrCreateTooltip(),
      (d: any) => `<strong>${d.data.label}</strong><br/>Nodes: ${d.data.value}`,
    );
  }
}
