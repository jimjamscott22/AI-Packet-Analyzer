import type { FlowDetail } from "../types/api";

interface FlowDetailPanelProps {
  flow: FlowDetail | null;
}

export function FlowDetailPanel({ flow }: FlowDetailPanelProps) {
  if (!flow) {
    return (
      <aside className="panel detail-panel">
        <div className="section-label">Inspector</div>
        <p>Select a flow to inspect evidence and normalized metadata.</p>
      </aside>
    );
  }

  return (
    <aside className="panel detail-panel">
      <div className="section-label">Inspector</div>
      <h2>{flow.classification}</h2>
      <dl className="detail-grid">
        <div>
          <dt>Direction</dt>
          <dd>{flow.directionality}</dd>
        </div>
        <div>
          <dt>Duration</dt>
          <dd>{flow.duration_seconds.toFixed(2)}s</dd>
        </div>
        <div>
          <dt>Packets</dt>
          <dd>{flow.packet_count}</dd>
        </div>
        <div>
          <dt>Bytes</dt>
          <dd>{flow.byte_count}</dd>
        </div>
      </dl>
      <div className="detail-block">
        <h3>Evidence</h3>
        {flow.evidence.length ? (
          <ul>
            {flow.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p>No evidence captured.</p>
        )}
      </div>
      <div className="detail-block">
        <h3>Metadata</h3>
        <pre>{JSON.stringify(flow.metadata, null, 2)}</pre>
      </div>
      <div className="detail-block">
        <h3>LLM Review</h3>
        {flow.llm_decision ? (
          <div className="llm-card">
            <strong>{flow.llm_decision.classification}</strong>
            <p>{flow.llm_decision.rationale}</p>
            <span>{Math.round(flow.llm_decision.confidence * 100)}% confidence</span>
          </div>
        ) : (
          <p>LLM review not available for this flow.</p>
        )}
      </div>
    </aside>
  );
}
