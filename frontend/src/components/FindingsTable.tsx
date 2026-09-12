import type { FindingRecord } from "../types/api";

interface FindingsTableProps {
  findings: FindingRecord[];
  total: number;
  severityFilter: string;
  sourceFilter: string;
  search: string;
  page: number;
  pageSize: number;
  selectedFindingId?: string;
  onSeverityChange: (value: string) => void;
  onSourceChange: (value: string) => void;
  onSearchChange: (value: string) => void;
  onPageChange: (page: number) => void;
  onSelectFinding: (finding: FindingRecord) => void;
}

export function FindingsTable({
  findings,
  total,
  severityFilter,
  sourceFilter,
  search,
  page,
  pageSize,
  selectedFindingId,
  onSeverityChange,
  onSourceChange,
  onSearchChange,
  onPageChange,
  onSelectFinding,
}: FindingsTableProps) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  return (
    <section className="panel">
      <div className="table-header">
        <div>
          <div className="section-label">Findings</div>
          <h2>Flagged behaviors</h2>
          <p>
            {total} result{total === 1 ? "" : "s"} across page {page} of {pageCount}
          </p>
        </div>
        <div className="toolbar">
          <input value={search} onChange={(event) => onSearchChange(event.target.value)} placeholder="Search findings" />
          <select value={sourceFilter} onChange={(event) => onSourceChange(event.target.value)}>
            <option value="ALL">All sources</option>
            <option value="heuristic">Heuristic</option>
            <option value="llm">LLM</option>
          </select>
          <select value={severityFilter} onChange={(event) => onSeverityChange(event.target.value)}>
            <option value="ALL">All severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>
      <div className="table">
        <div className="table-row table-row--head table-row--finding">
          <span>Type</span>
          <span>Severity</span>
          <span>Confidence</span>
          <span>Source</span>
          <span>Evidence</span>
        </div>
        {findings.map((finding) => (
          <button
            type="button"
            className={`table-row table-row--finding table-row--button ${selectedFindingId === finding.id ? "is-active" : ""}`}
            key={finding.id}
            onClick={() => onSelectFinding(finding)}
          >
            <span>{finding.title || finding.type}</span>
            <span className={`badge badge--${finding.severity}`}>{finding.severity}</span>
            <span>{Math.round(finding.confidence * 100)}%</span>
            <span>{finding.source}</span>
            <span className="finding-evidence">
              <strong>{finding.summary}</strong>
              {finding.evidence.slice(0, 2).map((item) => (
                <em key={item}>{item}</em>
              ))}
              <em>
                {finding.flow_ids.length
                  ? `${finding.flow_ids.length} related flow${finding.flow_ids.length === 1 ? "" : "s"}`
                  : "No linked flows"}
              </em>
            </span>
          </button>
        ))}
      </div>
      <div className="pagination">
        <button type="button" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
          Previous
        </button>
        <span>
          Page {page} / {pageCount}
        </span>
        <button type="button" disabled={page >= pageCount} onClick={() => onPageChange(page + 1)}>
          Next
        </button>
      </div>
    </section>
  );
}
