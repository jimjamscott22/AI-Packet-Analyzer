import type { FlowListItem } from "../types/api";

interface FlowExplorerProps {
  flows: FlowListItem[];
  protocol: string;
  search: string;
  onProtocolChange: (value: string) => void;
  onSearchChange: (value: string) => void;
  onSelectFlow: (flowId: string) => void;
  selectedFlowId?: string;
}

export function FlowExplorer({
  flows,
  protocol,
  search,
  onProtocolChange,
  onSearchChange,
  onSelectFlow,
  selectedFlowId,
}: FlowExplorerProps) {
  return (
    <section className="panel">
      <div className="table-header">
        <div>
          <div className="section-label">Flows</div>
          <h2>Explorer</h2>
        </div>
        <div className="toolbar">
          <select value={protocol} onChange={(event) => onProtocolChange(event.target.value)}>
            <option value="ALL">All protocols</option>
            <option value="DNS">DNS</option>
            <option value="HTTP">HTTP</option>
            <option value="TLS">TLS</option>
            <option value="OTHER">Other</option>
          </select>
          <input value={search} onChange={(event) => onSearchChange(event.target.value)} placeholder="Search by host" />
        </div>
      </div>
      <div className="flow-list">
        {flows.map((flow) => (
          <button
            type="button"
            key={flow.id}
            className={`flow-row ${selectedFlowId === flow.id ? "is-active" : ""}`}
            onClick={() => onSelectFlow(flow.id)}
          >
            <div>
              <strong>{flow.protocol}</strong>
              <span>
                {flow.src_ip}:{flow.src_port ?? "-"} → {flow.dst_ip}:{flow.dst_port ?? "-"}
              </span>
            </div>
            <div>
              <span>{flow.packet_count} pkts</span>
              <span>{flow.byte_count} bytes</span>
              <span>{Math.round(flow.score * 100)} score</span>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}
