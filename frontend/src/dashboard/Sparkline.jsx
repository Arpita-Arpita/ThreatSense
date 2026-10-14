// Tiny SVG sparkline (task 1.16)
export default function Sparkline({ points = [], color = "#2b54ff", w = 74, h = 30 }) {
  if (!points.length) return <svg width={w} height={h} />;
  const max = Math.max(...points), min = Math.min(...points);
  const X = (i) => (i / (points.length - 1 || 1)) * w;
  const Y = (v) => h - 2 - ((v - min) / ((max - min) || 1)) * (h - 6);
  const line = points.map((v, i) => `${i ? "L" : "M"}${X(i).toFixed(1)} ${Y(v).toFixed(1)}`).join(" ");
  const area = `${line} L${w} ${h} L0 ${h} Z`;
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
      <path d={area} fill={color} opacity="0.13" />
      <path d={line} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
