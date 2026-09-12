import { useEffect, useState } from "react";

import { getFindings, getFlowDetail, getFlows, getHealth, getJob, getSummary, uploadPcap } from "./api/client";
import { FindingsTable } from "./components/FindingsTable";
import { FlowDetailPanel } from "./components/FlowDetailPanel";
import { FlowExplorer } from "./components/FlowExplorer";
import { StatusStrip } from "./components/StatusStrip";
import { SummaryPanel } from "./components/SummaryPanel";
import { UploadPanel } from "./components/UploadPanel";
import type { AnalysisJob, FindingRecord, FlowDetail, FlowListItem, HealthStatus, JobSummary } from "./types/api";

const PAGE_SIZE = 10;

export default function App() {
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [summary, setSummary] = useState<JobSummary | null>(null);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [flows, setFlows] = useState<FlowListItem[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [flowsTotal, setFlowsTotal] = useState(0);
  const [selectedFlow, setSelectedFlow] = useState<FlowDetail | null>(null);
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [flowSearch, setFlowSearch] = useState("");
  const [findingSearch, setFindingSearch] = useState("");
  const [flowPage, setFlowPage] = useState(1);
  const [findingPage, setFindingPage] = useState(1);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void getHealth()
      .then((nextHealth) => {
        if (!cancelled) {
          setHealth(nextHealth);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setHealth(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!job?.id) {
      return;
    }

    let cancelled = false;
    let timer: number | undefined;

    const refresh = async () => {
      try {
        const latestJob = await getJob(job.id);
        if (cancelled) {
          return;
        }
        setJob(latestJob);
        if (latestJob.status === "processing" || latestJob.status === "queued") {
          timer = window.setTimeout(refresh, 2000);
          return;
        }

        const [nextSummary, nextFindings, nextFlows] = await Promise.all([
          getSummary(job.id),
          getFindings(job.id, {
            severity: severityFilter,
            source: sourceFilter,
            search: findingSearch,
            offset: (findingPage - 1) * PAGE_SIZE,
            limit: PAGE_SIZE,
          }),
          getFlows(job.id, {
            protocol: protocolFilter,
            search: flowSearch,
            offset: (flowPage - 1) * PAGE_SIZE,
            limit: PAGE_SIZE,
          }),
        ]);
        if (!cancelled) {
          setSummary(nextSummary);
          setFindings(nextFindings.items);
          setFindingsTotal(nextFindings.total);
          setFlows(nextFlows.items);
          setFlowsTotal(nextFlows.total);
        }
      } catch (caught) {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Unknown error");
        }
      }
    };

    void refresh();
    return () => {
      cancelled = true;
      if (timer) {
        window.clearTimeout(timer);
      }
    };
  }, [job?.id, protocolFilter, severityFilter, sourceFilter, flowSearch, findingSearch, flowPage, findingPage]);

  async function handleUpload(file: File) {
    try {
      setIsUploading(true);
      setError(null);
      setSelectedFlow(null);
      setSelectedFindingId(null);
      const createdJob = await uploadPcap(file);
      setJob(createdJob);
      setSummary(null);
      setFindings([]);
      setFlows([]);
      setFindingsTotal(0);
      setFlowsTotal(0);
      setFlowPage(1);
      setFindingPage(1);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Upload failed");
    } finally {
      setIsUploading(false);
    }
  }

  async function handleSelectFlow(flowId: string, findingId?: string) {
    if (!job) {
      return;
    }
    try {
      const detail = await getFlowDetail(job.id, flowId);
      setSelectedFlow(detail);
      setSelectedFindingId(findingId ?? null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to load flow detail");
    }
  }

  async function handleSelectFinding(finding: FindingRecord) {
    const flowId = finding.flow_ids[0];
    if (!flowId) {
      setSelectedFindingId(finding.id);
      return;
    }
    await handleSelectFlow(flowId, finding.id);
  }

  return (
    <main className="app-shell">
      <div className="grid-backdrop" />
      <UploadPanel onUpload={handleUpload} isUploading={isUploading} />
      <StatusStrip job={job} />
      {error ? <div className="error-banner">{error}</div> : null}
      <div className="workspace">
        <div className="workspace-main">
          <SummaryPanel summary={summary} health={health} />
          <FindingsTable
            findings={findings}
            total={findingsTotal}
            severityFilter={severityFilter}
            sourceFilter={sourceFilter}
            search={findingSearch}
            page={findingPage}
            pageSize={PAGE_SIZE}
            selectedFindingId={selectedFindingId ?? undefined}
            onSeverityChange={(value) => {
              setSeverityFilter(value);
              setFindingPage(1);
            }}
            onSourceChange={(value) => {
              setSourceFilter(value);
              setFindingPage(1);
            }}
            onSearchChange={(value) => {
              setFindingSearch(value);
              setFindingPage(1);
            }}
            onPageChange={setFindingPage}
            onSelectFinding={handleSelectFinding}
          />
          <FlowExplorer
            flows={flows}
            total={flowsTotal}
            protocol={protocolFilter}
            search={flowSearch}
            page={flowPage}
            pageSize={PAGE_SIZE}
            onProtocolChange={(value) => {
              setProtocolFilter(value);
              setFlowPage(1);
            }}
            onSearchChange={(value) => {
              setFlowSearch(value);
              setFlowPage(1);
            }}
            onPageChange={setFlowPage}
            onSelectFlow={handleSelectFlow}
            selectedFlowId={selectedFlow?.id}
          />
        </div>
        <FlowDetailPanel flow={selectedFlow} />
      </div>
    </main>
  );
}
