import type { JobSummary, SummaryMetric } from "../types/api";

interface SummaryPanelProps {
  summary: JobSummary | null;
}

function MetricBar({ label, value, total }: { label: string; value: number; total: number }) {
  const width = total === 0 ? 0 : (value / total) * 100;
  return (
    <div className="metric-bar">
      <div className="metric-bar__head">
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      <div className="metric-bar__track">
        <div className="metric-bar__fill" style={{ width: `${width}%` }} />
      </div>
    </div>
  );
}

function maxValue(items: SummaryMetric[], key: "count" | "bytes") {
  return items.reduce((highest, item) => Math.max(highest, Number(item[key] ?? 0)), 0);
}

export function SummaryPanel({ summary }: SummaryPanelProps) {
  if (!summary) {
    return (
      <section className="panel">
        <div className="section-label">Overview</div>
        <p>No analysis loaded yet.</p>
      </section>
    );
  }

  return (
    <section className="panel summary-grid">
      <div>
        <div className="section-label">Overview</div>
        <div className="summary-kpis">
          <article>
            <span>Findings</span>
            <strong>{summary.finding_count}</strong>
          </article>
          <article>
            <span>Protocols</span>
            <strong>{summary.top_protocols.length}</strong>
          </article>
          <article>
            <span>LLM</span>
            <strong>{summary.llm_enabled ? "Enabled" : "Disabled"}</strong>
          </article>
        </div>
      </div>
      <div>
        <h2>Top protocols</h2>
        {summary.top_protocols.map((item) => (
          <MetricBar
            key={item.protocol}
            label={item.protocol ?? "Unknown"}
            value={Number(item.count ?? 0)}
            total={maxValue(summary.top_protocols, "count")}
          />
        ))}
      </div>
      <div>
        <h2>Top talkers</h2>
        {summary.top_talkers.map((item) => (
          <MetricBar
            key={item.host}
            label={item.host ?? "Unknown"}
            value={Number(item.bytes ?? 0)}
            total={maxValue(summary.top_talkers, "bytes")}
          />
        ))}
      </div>
    </section>
  );
}
