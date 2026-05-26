import { Component, OnInit, ElementRef, ViewChild, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../services/api/api';
import * as d3 from 'd3';
import {
  CircleDot,
  GitBranch,
  Globe,
  LucideAngularModule,
  Network,
  RefreshCw,
  Router,
  Server,
  TriangleAlert,
  X,
} from 'lucide-angular';

@Component({
  selector: 'app-network-map',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './network-map.html',
  styleUrl: './network-map.css',
})
export class NetworkMap implements OnInit {
  @ViewChild('mapSvg', { static: true }) svgRef!: ElementRef;

  nodeCount: number = 0;
  edgeCount: number = 0;
  loading: boolean = true;
  selectedNode: any = null;
  lastUpdated: string = '--';

  CircleDotIcon = CircleDot;
  GitBranchIcon = GitBranch;
  GlobeIcon = Globe;
  NetworkIcon = Network;
  RefreshIcon = RefreshCw;
  RouterIcon = Router;
  ServerIcon = Server;
  ThreatIcon = TriangleAlert;
  XIcon = X;

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit() {
    this.loadMap();
  }

  getNodeIcon(node: any): string {
    if (node.threat) return '!';
    if (node.type === 'internal') return 'IN';
    if (node.id?.includes(':443') || node.dstPort === 443) return 'TLS';
    if (node.id?.includes(':53') || node.dstPort === 53) return 'DNS';
    return 'EX';
  }

  getNodeKindLabel(node: any): string {
    if (node?.threat) return 'Threat Indicator';
    return node?.type === 'internal' ? 'Internal Host' : 'External Server';
  }

  getNodeTypeClass(node: any): string {
    if (node?.threat) return 'threat';
    return node?.type === 'internal' ? 'internal' : 'external';
  }

  clearSelection() {
    this.selectedNode = null;
    d3.select(this.svgRef.nativeElement).selectAll('.topology-node').classed('is-selected', false);
  }

  loadMap() {
    this.loading = true;
    this.selectedNode = null;
    this.api.getNetworkMap().subscribe({
      next: (data: any) => {
        const nodes = data.nodes || [];
        const edges = data.edges || [];
        this.nodeCount = data.total_nodes ?? nodes.length;
        this.edgeCount = data.total_edges ?? edges.length;
        this.lastUpdated = new Date().toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });
        this.loading = false;
        this.cdr.detectChanges();
        setTimeout(() => this.renderGraph(nodes, edges), 100);
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  renderGraph(nodes: any[], edges: any[]) {
    const svgEl = this.svgRef.nativeElement;
    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    const width = svgEl.clientWidth || 1000;
    const height = svgEl.clientHeight || 600;

    const defs = svg.append('defs');

    const glowFilter = defs.append('filter').attr('id', 'glow');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    defs
      .append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#7ca3ff70');

    const g = svg.append('g');
    svg.call(
      d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.1, 8])
        .on('zoom', (event) => g.attr('transform', event.transform))
    );

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        'link',
        d3
          .forceLink(edges)
          .id((d: any) => d.id)
          .distance((d: any) => {
            const w = Math.log((d.connections || 1) + 1);
            return Math.max(60, 150 - w * 10);
          })
      )
      .force(
        'charge',
        d3.forceManyBody().strength((d: any) => (d.type === 'internal' ? -440 : -220))
      )
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(40));

    const link = g
      .append('g')
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke', (d: any) => {
        const w = Math.log((d.connections || 1) + 1);
        return w > 3 ? '#f8a01080' : '#7ca3ff46';
      })
      .attr('stroke-width', (d: any) => Math.min(Math.log((d.connections || 1) + 1), 4))
      .attr('stroke-linecap', 'round')
      .attr('marker-end', 'url(#arrow)');

    const edgeLabel = g
      .append('g')
      .selectAll('text')
      .data(edges.filter((d: any) => d.connections > 5))
      .join('text')
      .attr('fill', '#f8a010b0')
      .attr('font-size', '8px')
      .attr('font-family', 'monospace')
      .attr('font-weight', '700')
      .text((d: any) => d.connections);

    const node = g
      .append('g')
      .selectAll<SVGGElement, any>('g')
      .data(nodes)
      .join('g')
      .attr('class', (d: any) => `topology-node ${this.getNodeTypeClass(d)}`)
      .style('cursor', 'pointer')
      .call(
        d3
          .drag<SVGGElement, any>()
          .on('start', (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d: any) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d: any) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on('click', (event, d: any) => {
        this.selectedNode = d;
        node.classed('is-selected', (n: any) => n.id === d.id);
        this.cdr.detectChanges();
      });

    node
      .append('circle')
      .attr('r', (d: any) => (d.type === 'internal' ? 22 : 18))
      .attr('fill', (d: any) => {
        if (d.threat) return '#2b1214';
        return d.type === 'internal' ? '#0c2a2c' : '#101c35';
      })
      .attr('stroke', (d: any) => {
        if (d.threat) return '#ff716a';
        return d.type === 'internal' ? '#69f6b8' : '#7ca3ff';
      })
      .attr('stroke-width', 1.4)
      .attr('filter', (d: any) => (d.type === 'internal' ? 'url(#glow)' : ''));

    node
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('fill', (d: any) => {
        if (d.threat) return '#ffb3ad';
        return d.type === 'internal' ? '#9ffbd0' : '#b8ccff';
      })
      .attr('font-size', (d: any) => (this.getNodeIcon(d).length > 2 ? '8px' : '10px'))
      .attr('font-family', 'monospace')
      .attr('font-weight', '800')
      .text((d: any) => this.getNodeIcon(d));

    node
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('y', 30)
      .attr('fill', (d: any) => {
        if (d.threat) return '#ff918b';
        return d.type === 'internal' ? '#69f6b8' : '#9bb7ff';
      })
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .text((d: any) => {
        if (d.id?.includes(':') && d.id?.length > 15) {
          return d.id.substring(0, 12) + '...';
        }
        return d.id;
      });

    node
      .filter((d: any) => (d.connections || 0) > 0)
      .append('text')
      .attr('x', 16)
      .attr('y', -16)
      .attr('text-anchor', 'middle')
      .attr('fill', '#d8deec')
      .attr('font-size', '8px')
      .attr('font-family', 'monospace')
      .attr('font-weight', '800')
      .text((d: any) => (d.connections > 0 ? `${d.connections}` : ''));

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
