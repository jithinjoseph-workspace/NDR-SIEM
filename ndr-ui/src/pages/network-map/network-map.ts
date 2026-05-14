import { Component, OnInit, ElementRef, ViewChild, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../services/api/api';
import * as d3 from 'd3';

@Component({
  selector: 'app-network-map',
  standalone: true,
  imports: [CommonModule],
  template: `
<div class="p-8 h-screen flex flex-col bg-[#0a0f1e]">
  <!-- Header -->
  <div class="flex items-center justify-between mb-6">
    <div>
      <h2 class="text-2xl font-display font-bold text-white uppercase tracking-tight">
        Network Topology Map
      </h2>
      <p class="text-on-surface-variant text-sm mt-1">
        Live host communication graph — last 1 hour
      </p>
    </div>
    <div class="flex items-center gap-6">
      <!-- Legend -->
      <div class="flex items-center gap-4 text-[11px] bg-surface-container-highest px-4 py-2 rounded-lg border border-outline/10">
        <span class="flex items-center gap-2 text-on-surface-variant">
          <span class="text-lg">🖥️</span> Internal Host
        </span>
        <span class="flex items-center gap-2 text-on-surface-variant">
          <span class="text-lg">🌐</span> External Server
        </span>
        <span class="flex items-center gap-2 text-on-surface-variant">
          <span class="text-lg">⚠️</span> Threat
        </span>
      </div>
      <!-- Stats -->
      <div class="flex gap-3">
        <div class="bg-surface-container-highest px-4 py-2 rounded-lg border border-outline/10 text-center">
          <div class="text-[10px] text-on-surface-variant uppercase">Nodes</div>
          <div class="text-white font-bold font-mono">{{ nodeCount }}</div>
        </div>
        <div class="bg-surface-container-highest px-4 py-2 rounded-lg border border-outline/10 text-center">
          <div class="text-[10px] text-on-surface-variant uppercase">Connections</div>
          <div class="text-white font-bold font-mono">{{ edgeCount }}</div>
        </div>
      </div>
      <button (click)="loadMap()"
        class="bg-primary text-black text-xs font-bold px-4 py-2 rounded hover:bg-primary/90 transition-all">
        ↻ Refresh
      </button>
    </div>
  </div>

  <!-- Map Container -->
  <div class="flex-1 bg-[#0d1226] rounded-xl border border-outline/10 overflow-hidden relative">

    <!-- Loading -->
    <div *ngIf="loading"
         class="absolute inset-0 flex flex-col items-center justify-center text-on-surface-variant z-10">
      <div class="text-4xl mb-4 animate-pulse">🔍</div>
      <p class="text-sm animate-pulse">Mapping network topology...</p>
    </div>

    <!-- Empty -->
    <div *ngIf="!loading && nodeCount === 0"
         class="absolute inset-0 flex flex-col items-center justify-center text-on-surface-variant">
      <div class="text-4xl mb-4">📡</div>
      <p class="text-sm">No network data yet</p>
      <p class="text-xs mt-1">Start monitoring to see topology</p>
    </div>

    <!-- Selected node info -->
    <div *ngIf="selectedNode"
         class="absolute top-4 right-4 bg-surface-container-highest border border-outline/20 rounded-xl p-4 w-64 z-10">
      <div class="flex items-center gap-3 mb-3">
        <span class="text-2xl">{{ getNodeIcon(selectedNode) }}</span>
        <div>
          <div class="text-white text-xs font-bold font-mono">{{ selectedNode.id }}</div>
          <div class="text-[10px] text-on-surface-variant uppercase">
            {{ selectedNode.type === 'internal' ? 'Internal Host' : 'External Server' }}
          </div>
        </div>
      </div>
      <div class="space-y-1 text-[11px]">
        <div class="flex justify-between">
          <span class="text-on-surface-variant">Connections:</span>
          <span class="text-white font-mono">{{ selectedNode.connections || 0 }}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-on-surface-variant">Type:</span>
          <span [class]="selectedNode.type === 'internal' ? 'text-primary' : 'text-red-400'">
            {{ selectedNode.type }}
          </span>
        </div>
      </div>
      <button (click)="selectedNode = null"
              class="mt-3 w-full text-[10px] text-on-surface-variant hover:text-white transition-colors">
        ✕ Close
      </button>
    </div>

    <svg #mapSvg class="w-full h-full"></svg>
  </div>
</div>
  `
})
export class NetworkMap implements OnInit {
  @ViewChild('mapSvg', { static: true }) svgRef!: ElementRef;

  nodeCount: number = 0;
  edgeCount: number = 0;
  loading: boolean = true;
  selectedNode: any = null;

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.loadMap();
  }

  getNodeIcon(node: any): string {
    if (node.threat) return '⚠️';
    if (node.type === 'internal') return '🖥️';
    // Classify external by common ports/services
    if (node.id?.includes(':443') || node.dstPort === 443) return '🔒';
    if (node.id?.includes(':53')  || node.dstPort === 53)  return '📡';
    return '🌐';
  }

  loadMap() {
    this.loading = true;
    this.selectedNode = null;
    this.api.getNetworkMap().subscribe({
      next: (data: any) => {
        this.nodeCount = data.total_nodes || 0;
        this.edgeCount = data.total_edges || 0;
        this.loading = false;
        this.cdr.detectChanges();
        setTimeout(() => this.renderGraph(data.nodes || [], data.edges || []), 100);
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  renderGraph(nodes: any[], edges: any[]) {
    const svgEl = this.svgRef.nativeElement;
    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    const width  = svgEl.clientWidth  || 1000;
    const height = svgEl.clientHeight || 600;

    // Background grid pattern
    const defs = svg.append('defs');

    // Glow filter for internal nodes
    const glowFilter = defs.append('filter').attr('id', 'glow');
    glowFilter.append('feGaussianBlur')
      .attr('stdDeviation', '3').attr('result', 'coloredBlur');
    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Arrow marker
    defs.append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#69f6b840');

    // Main group with zoom
    const g = svg.append('g');
    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.1, 8])
        .on('zoom', (event) => g.attr('transform', event.transform))
    );

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges)
        .id((d: any) => d.id)
        .distance((d: any) => {
          const w = Math.log((d.connections || 1) + 1);
          return Math.max(60, 150 - w * 10);
        })
      )
      .force('charge', d3.forceManyBody()
        .strength((d: any) => d.type === 'internal' ? -400 : -200)
      )
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(40));

    // Draw edges
    const link = g.append('g').selectAll('line')
      .data(edges).join('line')
      .attr('stroke', (d: any) => {
        const w = Math.log((d.connections || 1) + 1);
        return w > 3 ? '#f8717140' : '#69f6b830';
      })
      .attr('stroke-width', (d: any) => Math.min(Math.log((d.connections || 1) + 1), 4))
      .attr('marker-end', 'url(#arrow)');

    // Edge labels (connection count)
    const edgeLabel = g.append('g').selectAll('text')
      .data(edges.filter((d: any) => d.connections > 5))
      .join('text')
      .attr('fill', '#69f6b860')
      .attr('font-size', '8px')
      .attr('font-family', 'monospace')
      .text((d: any) => d.connections);

    // Draw nodes
    const node = g.append('g').selectAll<SVGGElement, any>('g')
      .data(nodes).join('g')
      .style('cursor', 'pointer')
      .call(
        d3.drag<SVGGElement, any>()
          .on('start', (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x; d.fy = d.y;
          })
          .on('drag', (event, d: any) => {
            d.fx = event.x; d.fy = event.y;
          })
          .on('end', (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null; d.fy = null;
          })
      )
      .on('click', (event, d: any) => {
        this.selectedNode = d;
        this.cdr.detectChanges();
      });

    // Node background circle
    node.append('circle')
      .attr('r', (d: any) => d.type === 'internal' ? 22 : 18)
      .attr('fill', (d: any) => d.type === 'internal' ? '#0d1f2d' : '#1f0d0d')
      .attr('stroke', (d: any) => d.type === 'internal' ? '#69f6b850' : '#f8717150')
      .attr('stroke-width', 1.5)
      .attr('filter', (d: any) => d.type === 'internal' ? 'url(#glow)' : '');

    // Node emoji icon
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('font-size', (d: any) => d.type === 'internal' ? '16px' : '13px')
      .text((d: any) => this.getNodeIcon(d));

    // Node IP label
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('y', 30)
      .attr('fill', (d: any) => d.type === 'internal' ? '#69f6b8' : '#f87171')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .text((d: any) => {
        // Shorten IPv6
        if (d.id?.includes(':') && d.id?.length > 15) {
          return d.id.substring(0, 12) + '...';
        }
        return d.id;
      });

    // Connection count badge
    node.filter((d: any) => (d.connections || 0) > 0)
      .append('text')
      .attr('x', 16).attr('y', -16)
      .attr('text-anchor', 'middle')
      .attr('fill', '#a4abbf')
      .attr('font-size', '8px')
      .attr('font-family', 'monospace')
      .text((d: any) => d.connections > 0 ? `${d.connections}` : '');

    // Tick update
    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      edgeLabel
        .attr('x', (d: any) => (d.source.x + d.target.x) / 2)
        .attr('y', (d: any) => (d.source.y + d.target.y) / 2);

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
    });
  }
}