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
        <h3>TLS Metadata</h3>
        {flow.protocol === "TLS" ? (
          <dl className="detail-grid detail-grid--compact">
            <div>
              <dt>SNI</dt>
              <dd>{stringValue(flow.metadata.sni)}</dd>
            </div>
            <div>
              <dt>Handshake Seen</dt>
              <dd>{booleanValue(flow.metadata.handshake_seen)}</dd>
            </div>
            <div>
              <dt>ALPN</dt>
              <dd>{listValue(flow.metadata.alpn_protocols)}</dd>
            </div>
            <div>
              <dt>JA3-like</dt>
              <dd>{listValue(flow.metadata.ja3_like_fingerprints)}</dd>
            </div>
          </dl>
        ) : (
          <p>Not a TLS flow.</p>
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

function stringValue(value: unknown): string {
  return typeof value === "string" && value ? value : "Unavailable";
}

function booleanValue(value: unknown): string {
  return typeof value === "boolean" ? (value ? "Yes" : "No") : "Unavailable";
}

function listValue(value: unknown): string {
  return Array.isArray(value) && value.length ? value.join(", ") : "Unavailable";
}
