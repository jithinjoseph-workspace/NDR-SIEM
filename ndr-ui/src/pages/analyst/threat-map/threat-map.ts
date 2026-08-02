import { Component, OnInit, OnDestroy, ElementRef, ViewChild, HostListener, NgZone, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import { LucideAngularModule, Radio, Shield, Target, TrendingUp } from 'lucide-angular';

export interface AttackSource {
  country: string;
  code: string;
  lat: number;
  lon: number;
  count: number;
  color: string;
  attacks?: { tag: string; count: number }[];
}

const ARC_COLORS = [
  '#f43f5e', '#fb7185', '#e11d48', '#be123c',
  '#f97316', '#ef4444', '#dc2626', '#fbbf24',
];

@Component({
  selector: 'app-threat-map',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './threat-map.html',
  styleUrl: './threat-map.css',
})
export class ThreatMap implements OnInit, OnDestroy {
  @ViewChild('mapContainer', { static: true }) mapRef!: ElementRef;

  attackSources: AttackSource[] = [];
  totalAttacks = 0;
  loading = true;
  selectedCountry: AttackSource | null = null;

  RadarIcon  = Radio;
  ShieldIcon = Shield;
  TargetIcon = Target;
  TrendIcon  = TrendingUp;

  private rafId?: number;
  private particles: Particle[] = [];
  private arcPaths: SVGPathElement[] = [];

  constructor(private http: HttpClient, private ngZone: NgZone, private cdr: ChangeDetectorRef) {}

  ngOnInit() { this.init(); }

  selectCountry(src: AttackSource) {
    this.selectedCountry = this.selectedCountry?.country === src.country ? null : src;
    this.ngZone.run(() => this.cdr.detectChanges());
  }

  tagLabel(tag: string): string {
    const labels: Record<string, string> = {
      'port-scan':            'Port Scan',
      'dns-beaconing':        'DNS Beaconing',
      'dns-tunneling':        'DNS Tunneling',
      'threat-intel':         'Known Malicious',
      'ids-alert':            'Agent-S Alert',
      'volume-anomaly':       'Volume Anomaly',
      'lateral-movement':     'Lateral Movement',
      'credential-stuffing':  'Credential Stuffing',
      'beaconing':            'C2 Beaconing',
      'slow-scan':            'Slow Scan',
      'data-staging':         'Data Staging',
      'internal-recon':       'Internal Recon',
      'new-external-contact': 'New External Contact',
      'icmp-flood':           'ICMP Flood',
      'nxdomain-flood':       'NX Domain Flood',
      'abnormal-hours':       'Abnormal Hours',
      'tls-cert-anomaly':     'TLS Cert Anomaly',
      'protocol-misuse':      'Protocol Misuse',
      'large-volume-exfil':   'Large Exfil',
      'sensitive-country':    'Sensitive Country',
      'sigma':                'Sigma Rule',
      'dga':                  'DGA Domain',
      'doh-evasion':          'DoH Evasion',
      'malicious-domain':     'Malicious Domain',
      'abnormal-rst':         'Abnormal RST',
      'ip-conflict':          'IP Conflict',
    };
    if (labels[tag]) return labels[tag];
    // Sigma / Suricata rule names — strip ET category prefix, replace vendor names
    const clean = tag
      .replace(/^ET\s+(INFO|SCAN|POLICY|ATTACK|MALWARE|TROJAN|EXPLOIT|WEB_SERVER)\s+/i, '')
      .replace(/suricata/gi, 'Agent-S')
      .replace(/zeek/gi, 'Agent-Z');
    return clean.length > 28 ? clean.substring(0, 26) + '…' : clean;
  }

  countryFlag(code: string): string {
    if (!code || code.length !== 2) return '🌍';
    return code.toUpperCase().replace(/./g, c =>
      String.fromCodePoint(127397 + c.charCodeAt(0))
    );
  }

  ngOnDestroy() {
    if (this.rafId) cancelAnimationFrame(this.rafId);
  }

  @HostListener('window:resize')
  onResize() { this.init(); }

  private async init() {
    if (this.rafId) cancelAnimationFrame(this.rafId);
    this.particles = [];
    this.arcPaths  = [];

    const [world, data] = await Promise.all([
      this.http.get('/assets/world-110m.json').toPromise(),
      this.http.get<any>('/api/threat-map').toPromise().catch(() => ({ countries: [] }))
    ]);

    const raw: any[] = data?.countries ?? [];
    this.attackSources = raw.map((c, i) => ({
      ...c,
      color: ARC_COLORS[i % ARC_COLORS.length]
    }));
    this.totalAttacks = this.attackSources.reduce((s, c) => s + c.count, 0);
    this.ngZone.run(() => {
      this.loading = false;
      this.cdr.detectChanges();
    });

    this.ngZone.runOutsideAngular(() => this.drawMap(world));
  }

  private drawMap(world: any) {
    const el   = this.mapRef.nativeElement;
    const W    = el.clientWidth  || 900;
    const H    = el.clientHeight || 480;

    d3.select(el).selectAll('*').remove();

    const svg = d3.select(el).append('svg')
      .attr('width', W).attr('height', H)
      .attr('viewBox', `0 0 ${W} ${H}`)
      .style('display', 'block');

    // ── SVG Filters (glow effects) ─────────────────────────
    const defs = svg.append('defs');

    const arcGlow = defs.append('filter').attr('id', 'arc-glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    arcGlow.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', '3').attr('result', 'blur');
    arcGlow.append('feMerge').selectAll('feMergeNode').data(['blur', 'SourceGraphic']).enter().append('feMergeNode').attr('in', (d: any) => d);

    const dotGlow = defs.append('filter').attr('id', 'dot-glow').attr('x', '-100%').attr('y', '-100%').attr('width', '300%').attr('height', '300%');
    dotGlow.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', '5').attr('result', 'blur');
    dotGlow.append('feMerge').selectAll('feMergeNode').data(['blur', 'SourceGraphic']).enter().append('feMergeNode').attr('in', (d: any) => d);

    const greenGlow = defs.append('filter').attr('id', 'green-glow').attr('x', '-100%').attr('y', '-100%').attr('width', '300%').attr('height', '300%');
    greenGlow.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', '6').attr('result', 'blur');
    greenGlow.append('feMerge').selectAll('feMergeNode').data(['blur', 'SourceGraphic']).enter().append('feMergeNode').attr('in', (d: any) => d);

    // Ocean radial gradient
    const oceanGrad = defs.append('radialGradient').attr('id', 'ocean-grad').attr('cx', '50%').attr('cy', '50%').attr('r', '55%');
    oceanGrad.append('stop').attr('offset', '0%').attr('stop-color', '#091828');
    oceanGrad.append('stop').attr('offset', '100%').attr('stop-color', '#040c18');

    const proj = d3.geoNaturalEarth1()
      .scale(W / 6.2)
      .translate([W / 2, H / 2]);

    const pathFn = d3.geoPath().projection(proj);

    // Ocean fill
    svg.append('path')
      .datum({ type: 'Sphere' } as any)
      .attr('d', pathFn as any)
      .attr('fill', 'url(#ocean-grad)');

    // Graticule — fine 20° grid
    const grat = d3.geoGraticule().step([20, 20]);
    svg.append('path')
      .datum(grat())
      .attr('d', pathFn as any)
      .attr('fill', 'none')
      .attr('stroke', 'rgba(34,197,94,0.06)')
      .attr('stroke-width', 0.4);

    // Countries — tinted blue-green land
    const countries = (topojson as any).feature(world, world.objects.countries);
    svg.selectAll('.land')
      .data((countries as any).features)
      .enter().append('path')
      .attr('class', 'land')
      .attr('d', pathFn as any)
      .attr('fill', '#0d2135')
      .attr('stroke', 'rgba(34,197,94,0.18)')
      .attr('stroke-width', 0.5);

    // Inner country borders
    svg.append('path')
      .datum((topojson as any).mesh(world, world.objects.countries, (a: any, b: any) => a !== b))
      .attr('d', pathFn as any)
      .attr('fill', 'none')
      .attr('stroke', 'rgba(100,180,140,0.1)')
      .attr('stroke-width', 0.3);

    // Sphere outline
    svg.append('path')
      .datum({ type: 'Sphere' } as any)
      .attr('d', pathFn as any)
      .attr('fill', 'none')
      .attr('stroke', 'rgba(34,197,94,0.12)')
      .attr('stroke-width', 1);

    const targetCoords: [number, number] = [80.0, 12.0];
    const targetXY = proj(targetCoords)!;

    const arcGroup      = svg.append('g').attr('class', 'arcs');
    const arcGlowGroup  = svg.append('g').attr('class', 'arcs-glow');
    const dotGroup      = svg.append('g').attr('class', 'dots');
    const particleGroup = svg.append('g').attr('class', 'particles');

    this.arcPaths = [];
    this.particles = [];

    this.attackSources.slice(0, 12).forEach((src, i) => {
      const srcXY = proj([src.lon, src.lat]);
      if (!srcXY) return;

      const lineData: any = { type: 'LineString', coordinates: [[src.lon, src.lat], targetCoords] };
      const totalLen = (() => {
        const tmp = arcGroup.append('path').datum(lineData).attr('d', pathFn as any).node() as SVGPathElement;
        const l = tmp.getTotalLength();
        tmp.remove();
        return l;
      })();

      // Glow copy (thick, blurred)
      arcGlowGroup.append('path')
        .datum(lineData)
        .attr('d', pathFn as any)
        .attr('fill', 'none')
        .attr('stroke', src.color)
        .attr('stroke-width', 4)
        .attr('stroke-opacity', 0)
        .attr('filter', 'url(#arc-glow)')
        .attr('stroke-dasharray', `${totalLen} ${totalLen}`)
        .attr('stroke-dashoffset', totalLen)
        .transition().delay(i * 180).duration(1400).ease(d3.easeLinear)
        .attr('stroke-dashoffset', 0)
        .attr('stroke-opacity', 0.3);

      // Sharp arc on top
      const arcEl = arcGroup.append('path')
        .datum(lineData)
        .attr('d', pathFn as any)
        .attr('fill', 'none')
        .attr('stroke', src.color)
        .attr('stroke-width', 1.5)
        .attr('stroke-opacity', 0)
        .attr('stroke-dasharray', `${totalLen} ${totalLen}`)
        .attr('stroke-dashoffset', totalLen);

      arcEl.transition().delay(i * 180).duration(1400).ease(d3.easeLinear)
        .attr('stroke-dashoffset', 0)
        .attr('stroke-opacity', 0.75);

      const pathNode = arcEl.node() as SVGPathElement;
      this.arcPaths.push(pathNode);

      // Pulsing source dot — size by count
      const dotR = this.sizeForCount(src.count);
      dotGroup.append('circle')
        .attr('cx', srcXY[0]).attr('cy', srcXY[1])
        .attr('r', 0).attr('fill', src.color).attr('opacity', 1)
        .attr('filter', 'url(#dot-glow)')
        .transition().delay(i * 180).duration(500)
        .attr('r', dotR);

      // Solid core dot
      dotGroup.append('circle')
        .attr('cx', srcXY[0]).attr('cy', srcXY[1])
        .attr('r', 0).attr('fill', '#fff').attr('opacity', 0.9)
        .transition().delay(i * 180).duration(500)
        .attr('r', Math.max(2, dotR * 0.45));

      // Expanding ring
      dotGroup.append('circle')
        .attr('cx', srcXY[0]).attr('cy', srcXY[1])
        .attr('r', 0).attr('fill', 'none')
        .attr('stroke', src.color).attr('stroke-width', 1.2).attr('opacity', 0)
        .call((sel: any) => this.pulseRing(sel, i * 180 + 400, dotR + 10));

      // Second slower ring
      dotGroup.append('circle')
        .attr('cx', srcXY[0]).attr('cy', srcXY[1])
        .attr('r', 0).attr('fill', 'none')
        .attr('stroke', src.color).attr('stroke-width', 0.7).attr('opacity', 0)
        .call((sel: any) => this.pulseRing(sel, i * 180 + 900, dotR + 18));

      // Country label — pill background so it's readable over map features
      const labelText = src.country;
      const lw = labelText.length * 5.8 + 12;
      const lh = 15;
      const lx2 = srcXY[0] + dotR + 6;
      const ly2 = srcXY[1] - lh / 2;

      dotGroup.append('rect')
        .attr('x', lx2 - 2).attr('y', ly2)
        .attr('width', lw).attr('height', lh)
        .attr('rx', 3)
        .attr('fill', 'rgba(4, 12, 24, 0.78)')
        .attr('stroke', 'rgba(255,255,255,0.06)')
        .attr('stroke-width', 0.5)
        .attr('opacity', 0)
        .transition().delay(i * 180 + 700).duration(500)
        .attr('opacity', 1);

      dotGroup.append('text')
        .attr('x', lx2 + 2)
        .attr('y', srcXY[1] + 4)
        .attr('fill', '#e2e8f0')
        .attr('font-size', '9px')
        .attr('font-family', 'JetBrains Mono, monospace')
        .attr('font-weight', '600')
        .attr('letter-spacing', '0.03em')
        .attr('opacity', 0)
        .text(labelText)
        .transition().delay(i * 180 + 700).duration(500)
        .attr('opacity', 0.95);

      // Transparent clickable overlay — covers dot + label pill
      const hitW = lw + dotR + 14;
      dotGroup.append('rect')
        .attr('x', srcXY[0] - dotR - 4)
        .attr('y', ly2 - 4)
        .attr('width', hitW)
        .attr('height', lh + 8)
        .attr('rx', 4)
        .attr('fill', 'transparent')
        .attr('cursor', 'pointer')
        .on('mouseenter', function() {
          d3.select(this).attr('fill', `${src.color}18`).attr('stroke', src.color)
            .attr('stroke-width', 0.8).attr('stroke-opacity', 0.4);
        })
        .on('mouseleave', function() {
          d3.select(this).attr('fill', 'transparent').attr('stroke', 'none');
        })
        .on('click', () => {
          this.ngZone.run(() => this.selectCountry(src));
        });

      // Particles — more for higher counts
      const pCount = Math.min(4, Math.ceil(Math.log2(src.count + 1)));
      setTimeout(() => {
        for (let p = 0; p < pCount; p++) {
          this.particles.push({
            path: pathNode,
            color: src.color,
            t: p / pCount,
            speed: 0.0018 + Math.random() * 0.0022,
            el: particleGroup.append('circle')
              .attr('r', 2.8)
              .attr('fill', src.color)
              .attr('filter', 'url(#dot-glow)')
              .attr('opacity', 0.9)
              .node() as SVGCircleElement,
          });
        }
      }, i * 180 + 1400);
    });

    // ── Target marker — pulsing green beacon ──────────────
    const tg = svg.append('g').attr('class', 'target');

    // Glow halo
    tg.append('circle')
      .attr('cx', targetXY[0]).attr('cy', targetXY[1])
      .attr('r', 14).attr('fill', 'rgba(34,197,94,0.12)')
      .attr('filter', 'url(#green-glow)');

    // Core dot
    tg.append('circle')
      .attr('cx', targetXY[0]).attr('cy', targetXY[1])
      .attr('r', 7).attr('fill', '#22c55e').attr('opacity', 1)
      .attr('filter', 'url(#green-glow)');

    // White inner
    tg.append('circle')
      .attr('cx', targetXY[0]).attr('cy', targetXY[1])
      .attr('r', 3).attr('fill', '#ffffff').attr('opacity', 0.95);

    // Expanding rings
    tg.append('circle')
      .attr('cx', targetXY[0]).attr('cy', targetXY[1])
      .attr('r', 7).attr('fill', 'none')
      .attr('stroke', '#22c55e').attr('stroke-width', 1.8).attr('opacity', 0)
      .call((sel: any) => this.pulseRing(sel, 0, 28));

    tg.append('circle')
      .attr('cx', targetXY[0]).attr('cy', targetXY[1])
      .attr('r', 7).attr('fill', 'none')
      .attr('stroke', '#22c55e').attr('stroke-width', 1).attr('opacity', 0)
      .call((sel: any) => this.pulseRing(sel, 700, 42));

    // Label — shown only on hover over the target beacon
    const lx = targetXY[0];
    const ly = targetXY[1] - 22;

    const labelG = tg.append('g')
      .attr('class', 'target-label')
      .attr('pointer-events', 'none')
      .style('opacity', '0')
      .style('transition', 'opacity 0.2s');

    labelG.append('rect')
      .attr('x', lx - 52).attr('y', ly - 12)
      .attr('width', 104).attr('height', 22)
      .attr('rx', 4)
      .attr('fill', 'rgba(4, 14, 26, 0.88)')
      .attr('stroke', 'rgba(34,197,94,0.35)')
      .attr('stroke-width', 1);

    labelG.append('text')
      .attr('x', lx).attr('y', ly)
      .attr('text-anchor', 'middle')
      .attr('fill', '#86efac')
      .attr('font-size', '9px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('font-weight', '700')
      .attr('letter-spacing', '0.1em')
      .text('YOUR NETWORK');

    labelG.append('text')
      .attr('x', lx).attr('y', ly + 9)
      .attr('text-anchor', 'middle')
      .attr('fill', 'rgba(134,239,172,0.55)')
      .attr('font-size', '7.5px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('letter-spacing', '0.06em')
      .text('▲ PROTECTED');

    // Show label only on hover
    tg.style('cursor', 'pointer')
      .on('mouseover', () => labelG.style('opacity', '1'))
      .on('mouseout',  () => labelG.style('opacity', '0'));

    // Start particle animation loop
    this.animate();
  }

  private animate() {
    this.particles.forEach(p => {
      p.t += p.speed;
      if (p.t > 1) p.t = 0;
      try {
        const len = p.path.getTotalLength();
        const pt  = p.path.getPointAtLength(p.t * len);
        d3.select(p.el).attr('cx', pt.x).attr('cy', pt.y);
      } catch (_) {}
    });
    this.rafId = requestAnimationFrame(() => this.animate());
  }

  private pulseRing(sel: any, delay: number, maxR = 18) {
    const startR = Math.max(3, maxR * 0.2);
    const repeat = () => {
      sel.attr('r', startR).attr('opacity', 0.9)
        .transition().delay(delay).duration(1600).ease(d3.easeCubicOut)
        .attr('r', maxR).attr('opacity', 0)
        .on('end', repeat);
      delay = 0; // only delay on first ring
    };
    repeat();
  }

  private sizeForCount(count: number): number {
    return Math.min(12, Math.max(5, Math.log2(count + 1) * 1.6));
  }
}

interface Particle {
  path: SVGPathElement;
  color: string;
  t: number;
  speed: number;
  el: SVGCircleElement;
}
