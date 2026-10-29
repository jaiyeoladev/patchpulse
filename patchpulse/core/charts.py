"""Dependency-free, server-rendered SVG charts (CSP-friendly: no inline styles or scripts)."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from markupsafe import Markup, escape


def _fmt_default(v: float) -> str:
    v = float(v)
    if v.is_integer():
        return f"{v:,.0f}"
    return f"{v:.2f}" if abs(v) < 10 else f"{v:,.1f}"


def hbar(
    items: Sequence[tuple[str, float] | tuple[str, float, str]],
    fmt: Callable[[float], str] = _fmt_default,
    width: int = 640,
    label_width: int = 190,
    row_height: int = 30,
    max_value: float | None = None,
    empty: str = "No data yet",
) -> Markup:
    """Horizontal bar chart. Each item is (label, value[, css-class])."""
    if not items:
        return Markup(f'<p class="muted">{escape(empty)}</p>')
    top = max_value or max((float(i[1]) for i in items), default=0) or 1
    value_width = 86
    bar_area = width - label_width - value_width
    height = row_height * len(items)
    parts = [
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Bar chart" preserveAspectRatio="xMinYMin meet">'
    ]
    for idx, item in enumerate(items):
        label, value = item[0], float(item[1])
        cls = item[2] if len(item) > 2 else "bar-accent"
        y = idx * row_height
        w = max(0.0, min(1.0, value / top)) * bar_area
        max_chars = max(12, int(label_width / 6.4))
        short = label if len(label) <= max_chars else label[: max_chars - 1] + "…"
        parts.append(
            f'<g><title>{escape(label)}: {escape(fmt(value))}</title>'
            f'<text class="chart-label" x="{label_width - 10}" y="{y + row_height / 2 + 4:.1f}" '
            f'text-anchor="end">{escape(short)}</text>'
            f'<rect class="chart-track" x="{label_width}" y="{y + 7}" width="{bar_area}" '
            f'height="{row_height - 14}" rx="4"/>'
            f'<rect class="{escape(cls)}" x="{label_width}" y="{y + 7}" width="{w:.1f}" '
            f'height="{row_height - 14}" rx="4"/>'
            f'<text class="chart-value" x="{label_width + bar_area + 8}" '
            f'y="{y + row_height / 2 + 4:.1f}">{escape(fmt(value))}</text></g>'
        )
    parts.append("</svg>")
    return Markup("".join(parts))


def meter(value: float, maximum: float, warn_below: float | None = None, width: int = 120) -> Markup:
    """Compact utilisation meter for table cells."""
    ratio = 0.0 if maximum <= 0 else max(0.0, min(1.0, value / maximum))
    cls = "bar-accent"
    if warn_below is not None and ratio < warn_below:
        cls = "bar-warn"
    return Markup(
        f'<svg class="meter" viewBox="0 0 {width} 10" width="{width}" height="10" role="img" '
        f'aria-label="{ratio:.0%}"><rect class="chart-track" x="0" y="0" width="{width}" height="10" rx="5"/>'
        f'<rect class="{cls}" x="0" y="0" width="{ratio * width:.1f}" height="10" rx="5"/></svg>'
    )


def stacked(segments: Sequence[tuple[str, float, str]], width: int = 640, height: int = 18) -> Markup:
    """Single stacked bar, e.g. findings by severity. segments = (label, value, css-class)."""
    total = sum(max(0.0, float(s[1])) for s in segments)
    if total <= 0:
        return Markup(
            f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="No data">'
            f'<rect class="chart-track" x="0" y="0" width="{width}" height="{height}" rx="6"/></svg>'
        )
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="Distribution">']
    x = 0.0
    for label, value, cls in segments:
        if value <= 0:
            continue
        w = float(value) / total * width
        parts.append(
            f'<rect class="{escape(cls)}" x="{x:.1f}" y="0" width="{max(w - 2, 1):.1f}" height="{height}" rx="3">'
            f"<title>{escape(label)}: {value:g}</title></rect>"
        )
        x += w
    parts.append("</svg>")
    return Markup("".join(parts))


def columns(
    items: Sequence[tuple[str, float]],
    width: int = 640,
    height: int = 170,
    fmt: Callable[[float], str] = _fmt_default,
    cls: str = "bar-accent",
) -> Markup:
    """Vertical columns (e.g. a timeline of upcoming renewals or a trend)."""
    if not items:
        return Markup('<p class="muted">No data yet</p>')
    top = max((float(v) for _, v in items), default=0) or 1
    n = len(items)
    gap = 8
    col_w = (width - gap * (n - 1)) / n
    chart_h = height - 34
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="Column chart">']
    for i, (label, value) in enumerate(items):
        h = max(0.0, float(value) / top) * (chart_h - 16)
        x = i * (col_w + gap)
        y = chart_h - h
        parts.append(
            f'<g><title>{escape(label)}: {escape(fmt(float(value)))}</title>'
            f'<rect class="{cls}" x="{x:.1f}" y="{y:.1f}" width="{col_w:.1f}" height="{max(h, 1):.1f}" rx="3"/>'
            f'<text class="chart-value small" x="{x + col_w / 2:.1f}" y="{y - 4:.1f}" text-anchor="middle">'
            f"{escape(fmt(float(value)))}</text>"
            f'<text class="chart-label small" x="{x + col_w / 2:.1f}" y="{height - 12}" text-anchor="middle">'
            f"{escape(label)}</text></g>"
        )
    parts.append("</svg>")
    return Markup("".join(parts))
