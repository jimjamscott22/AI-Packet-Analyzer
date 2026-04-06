import type { FindingRecord } from "../types/api";

interface FindingsTableProps {
  findings: FindingRecord[];
  severityFilter: string;
  onSeverityChange: (value: string) => void;
}

export function FindingsTable({ findings, severityFilter, onSeverityChange }: FindingsTableProps) {
  const visible = severityFilter === "ALL" ? findings : findings.filter((item) => item.severity === severityFilter);

  return (
    <section className="panel">
      <div className="table-header">
        <div>
          <div className="section-label">Findings</div>
          <h2>Flagged behaviors</h2>
        </div>
        <select value={severityFilter} onChange={(event) => onSeverityChange(event.target.value)}>
          <option value="ALL">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="info">Info</option>
        </select>
      </div>
      <div className="table">
        <div className="table-row table-row--head">
          <span>Type</span>
          <span>Severity</span>
          <span>Confidence</span>
          <span>Source</span>
          <span>Summary</span>
        </div>
        {visible.map((finding) => (
          <div className="table-row" key={finding.id}>
            <span>{finding.type}</span>
            <span className={`badge badge--${finding.severity}`}>{finding.severity}</span>
            <span>{Math.round(finding.confidence * 100)}%</span>
            <span>{finding.source}</span>
            <span>{finding.summary}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
