"""Generate BugCod3 vector logo (icon + wide banner). Text is converted to paths."""
import math
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

BLACK = "/usr/share/fonts/google-noto-cjk/NotoSansJP-Black.otf"
MONO = "/usr/share/fonts/liberation-mono/LiberationMono-Bold.ttf"

def text_path(font_path, text, size, x, y, tracking=0.0):
    """Return (svg path d, width) for text with baseline at y."""
    f = TTFont(font_path)
    gs = f.getGlyphSet(); cmap = f.getBestCmap(); upm = f["head"].unitsPerEm
    s = size / upm
    pen = SVGPathPen(gs)
    cx = 0.0
    hmtx = f["hmtx"]
    for ch in text:
        g = cmap[ord(ch)]
        tp = TransformPen(pen, (s, 0, 0, -s, x + cx, y))
        gs[g].draw(tp)
        cx += hmtx[g][0] * s + tracking
    return pen.getCommands(), cx - tracking

def text_width(font_path, text, size, tracking=0.0):
    return text_path(font_path, text, size, 0, 0, tracking)[1]

DEFS = """
<defs>
  <linearGradient id="g-main" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#22d3ee"/><stop offset="0.55" stop-color="#60a5fa"/><stop offset="1" stop-color="#a78bfa"/>
  </linearGradient>
  <linearGradient id="g-text" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#67e8f9"/><stop offset="0.5" stop-color="#93c5fd"/><stop offset="1" stop-color="#c4b5fd"/>
  </linearGradient>
  <linearGradient id="g-bg" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#0f1b2e"/><stop offset="1" stop-color="#070b12"/>
  </linearGradient>
  <radialGradient id="g-core" cx="0.5" cy="0.45" r="0.6">
    <stop offset="0" stop-color="#1e3a5f"/><stop offset="1" stop-color="#0a1220" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="g-sweep" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#22d3ee" stop-opacity="0"/><stop offset="1" stop-color="#22d3ee" stop-opacity="0.55"/>
  </linearGradient>
  <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
    <feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <filter id="soft" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="10"/></filter>
</defs>"""

def hexagon(cx, cy, r, rot=0):
    pts = []
    for i in range(6):
        a = math.radians(60 * i - 90 + rot)
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return pts

def rounded_poly(pts, rad):
    """Path for a polygon with rounded corners."""
    n = len(pts); d = []
    for i in range(n):
        p0, p1, p2 = pts[i - 1], pts[i], pts[(i + 1) % n]
        def toward(a, b, dist):
            vx, vy = b[0] - a[0], b[1] - a[1]; L = math.hypot(vx, vy)
            return (a[0] + vx / L * dist, a[1] + vy / L * dist)
        a = toward(p1, p0, rad); b = toward(p1, p2, rad)
        d.append(("M" if i == 0 else "L") + f"{a[0]:.1f},{a[1]:.1f}")
        d.append(f"Q{p1[0]:.1f},{p1[1]:.1f} {b[0]:.1f},{b[1]:.1f}")
    return " ".join(d) + "Z"

def icon(cx=256, cy=256, R=230):
    """Icon group centred at (cx,cy) designed in a 512 box (R = hex radius)."""
    k = R / 230.0
    def S(v): return v * k
    out = []
    hexp = rounded_poly(hexagon(cx, cy, R), S(34))
    hexi = rounded_poly(hexagon(cx, cy, R - S(22)), S(26))
    out.append(f'<path d="{hexp}" fill="url(#g-bg)"/>')
    out.append(f'<path d="{hexp}" fill="none" stroke="url(#g-main)" stroke-width="{S(12):.1f}"/>')
    out.append(f'<path d="{hexi}" fill="none" stroke="#22d3ee" stroke-opacity="0.18" stroke-width="{S(2):.1f}"/>')
    out.append(f'<circle cx="{cx}" cy="{cy}" r="{S(150):.1f}" fill="url(#g-core)"/>')
    # globe
    gr = S(140)
    g = [f'<g fill="none" stroke="#38bdf8" stroke-opacity="0.32" stroke-width="{S(2.2):.1f}">',
         f'<circle cx="{cx}" cy="{cy}" r="{gr:.1f}"/>',
         f'<ellipse cx="{cx}" cy="{cy}" rx="{gr*0.42:.1f}" ry="{gr:.1f}"/>',
         f'<ellipse cx="{cx}" cy="{cy}" rx="{gr*0.80:.1f}" ry="{gr:.1f}"/>',
         f'<line x1="{cx-gr:.1f}" y1="{cy}" x2="{cx+gr:.1f}" y2="{cy}"/>',
         f'<ellipse cx="{cx}" cy="{cy}" rx="{gr:.1f}" ry="{gr*0.38:.1f}"/>',
         '</g>']
    out += g
    # radar sweep (wedge from centre, 0..55deg up-right)
    a0, a1 = math.radians(-100), math.radians(-40)
    sx0, sy0 = cx + gr * math.cos(a0), cy + gr * math.sin(a0)
    sx1, sy1 = cx + gr * math.cos(a1), cy + gr * math.sin(a1)
    out.append(f'<path d="M{cx},{cy} L{sx0:.1f},{sy0:.1f} A{gr:.1f},{gr:.1f} 0 0 1 {sx1:.1f},{sy1:.1f} Z" fill="url(#g-sweep)" opacity="0.9"/>')
    out.append(f'<line x1="{cx}" y1="{cy}" x2="{sx1:.1f}" y2="{sy1:.1f}" stroke="#67e8f9" stroke-width="{S(3):.1f}" stroke-linecap="round" filter="url(#glow)"/>')
    # crosshair ticks
    t = []
    for ang in (0, 90, 180, 270):
        a = math.radians(ang)
        x1, y1 = cx + (gr + S(8)) * math.cos(a), cy + (gr + S(8)) * math.sin(a)
        x2, y2 = cx + (gr + S(30)) * math.cos(a), cy + (gr + S(30)) * math.sin(a)
        t.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}"/>')
    out.append(f'<g stroke="url(#g-main)" stroke-width="{S(6):.1f}" stroke-linecap="round">' + "".join(t) + "</g>")
    # edge nodes (CDN PoPs) with links
    nodes = [(-0.62, -0.55), (0.70, -0.30), (0.55, 0.62), (-0.78, 0.30), (0.05, 0.92), (0.30, -0.88)]
    pts = [(cx + gr * x, cy + gr * y) for x, y in nodes]
    links = [(0, 5), (5, 1), (1, 2), (2, 4), (4, 3), (3, 0)]
    out.append(f'<g stroke="#a78bfa" stroke-opacity="0.45" stroke-width="{S(1.8):.1f}" stroke-dasharray="{S(4):.1f} {S(5):.1f}">' +
               "".join(f'<line x1="{pts[a][0]:.1f}" y1="{pts[a][1]:.1f}" x2="{pts[b][0]:.1f}" y2="{pts[b][1]:.1f}"/>' for a, b in links) + "</g>")
    for i, (x, y) in enumerate(pts):
        col = "#22d3ee" if i % 2 == 0 else "#a78bfa"
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{S(7):.1f}" fill="{col}" filter="url(#glow)"/>')
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{S(3):.1f}" fill="#e0f2fe"/>')
    # bug
    by = cy + S(14)
    b = [f'<g filter="url(#glow)">']
    # legs
    legs = []
    for side in (-1, 1):
        for (sx, sy, mx, my, ex, ey) in ((22, -14, 48, -30, 62, -54), (26, 8, 56, 6, 74, -4), (22, 30, 46, 48, 58, 74)):
            legs.append(f'M{cx+side*S(sx):.1f},{by+S(sy):.1f} L{cx+side*S(mx):.1f},{by+S(my):.1f} L{cx+side*S(ex):.1f},{by+S(ey):.1f}')
    b.append(f'<path d="{" ".join(legs)}" fill="none" stroke="url(#g-main)" stroke-width="{S(7):.1f}" stroke-linecap="round" stroke-linejoin="round"/>')
    # antennae
    b.append(f'<path d="M{cx-S(10):.1f},{by-S(58):.1f} Q{cx-S(22):.1f},{by-S(86):.1f} {cx-S(40):.1f},{by-S(92):.1f} M{cx+S(10):.1f},{by-S(58):.1f} Q{cx+S(22):.1f},{by-S(86):.1f} {cx+S(40):.1f},{by-S(92):.1f}" fill="none" stroke="url(#g-main)" stroke-width="{S(5):.1f}" stroke-linecap="round"/>')
    b.append(f'<circle cx="{cx-S(40):.1f}" cy="{by-S(92):.1f}" r="{S(5):.1f}" fill="#67e8f9"/><circle cx="{cx+S(40):.1f}" cy="{by-S(92):.1f}" r="{S(5):.1f}" fill="#c4b5fd"/>')
    # head + body
    b.append(f'<ellipse cx="{cx}" cy="{by-S(46):.1f}" rx="{S(24):.1f}" ry="{S(18):.1f}" fill="#0b1626" stroke="url(#g-main)" stroke-width="{S(5):.1f}"/>')
    b.append(f'<ellipse cx="{cx}" cy="{by+S(10):.1f}" rx="{S(38):.1f}" ry="{S(50):.1f}" fill="#0b1626" stroke="url(#g-main)" stroke-width="{S(6):.1f}"/>')
    b.append('</g>')
    # body details: split line + circuit
    b.append(f'<line x1="{cx}" y1="{by-S(34):.1f}" x2="{cx}" y2="{by+S(56):.1f}" stroke="url(#g-main)" stroke-width="{S(3.5):.1f}"/>')
    circ = (f'M{cx-S(8):.1f},{by-S(12):.1f} h{-S(14):.1f} v{S(16):.1f} M{cx-S(8):.1f},{by+S(22):.1f} h{-S(18):.1f} '
            f'M{cx+S(8):.1f},{by-S(4):.1f} h{S(18):.1f} M{cx+S(8):.1f},{by+S(28):.1f} h{S(12):.1f} v{-S(12):.1f}')
    b.append(f'<path d="{circ}" fill="none" stroke="#38bdf8" stroke-opacity="0.75" stroke-width="{S(2.5):.1f}" stroke-linecap="round"/>')
    for (dx, dy) in ((-22, 4), (-26, 22), (26, -4), (20, 16)):
        b.append(f'<circle cx="{cx+S(dx):.1f}" cy="{by+S(dy):.1f}" r="{S(3):.1f}" fill="#a5f3fc"/>')
    # eyes
    b.append(f'<circle cx="{cx-S(10):.1f}" cy="{by-S(48):.1f}" r="{S(5.5):.1f}" fill="#34d399" filter="url(#glow)"/>')
    b.append(f'<circle cx="{cx+S(10):.1f}" cy="{by-S(48):.1f}" r="{S(5.5):.1f}" fill="#34d399" filter="url(#glow)"/>')
    out += b
    return "\n".join(out)

# ---------------- square logo
logo = f'<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">{DEFS}\n{icon()}\n</svg>\n'
open("assets/logo.svg", "w").write(logo)

# ---------------- wide banner (transparent bg, works on light + dark GitHub themes via own card)
W, H = 1280, 360
word, ww = text_path(BLACK, "BugCod3", 150, 0, 0)
sub_text = "IP · CDN · EDGE SCANNER"
subw = text_width(MONO, sub_text, 34, 9)
content_w = 300 + 50 + max(ww, subw)
x0 = (W - content_w) / 2
tx = x0 + 300 + 50
word, ww = text_path(BLACK, "BugCod3", 150, tx, 205)
sub, _ = text_path(MONO, sub_text, 34, tx + 6, 268, 9)
card = rounded_poly([(0, 0), (W, 0), (W, H), (0, H)], 36)
banner = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">{DEFS}
<path d="{card}" fill="url(#g-bg)"/>
<path d="{card}" fill="none" stroke="url(#g-main)" stroke-opacity="0.55" stroke-width="3"/>
<circle cx="{x0+150}" cy="{H/2}" r="160" fill="#22d3ee" opacity="0.10" filter="url(#soft)"/>
<circle cx="{W-180}" cy="40" r="180" fill="#a78bfa" opacity="0.10" filter="url(#soft)"/>
<g opacity="0.25" stroke="#38bdf8" stroke-width="1.5" fill="none">
  <path d="M{W-40},{H-34} h-120 l-22,-22 h-70"/><path d="M{W-40},{H-18} h-210 l-16,-16 h-50"/>
  <path d="M40,60 h90 l26,26 h50"/>
</g>
{icon(x0 + 150, H / 2, 140)}
<path d="{word}" fill="url(#g-text)"/>
<path d="{sub}" fill="#7dd3fc" fill-opacity="0.85"/>
<rect x="{tx+6}" y="292" width="{subw:.0f}" height="4" rx="2" fill="url(#g-main)" opacity="0.8"/>
</svg>
'''
open("assets/banner.svg", "w").write(banner)
print("ok", len(logo), len(banner))
