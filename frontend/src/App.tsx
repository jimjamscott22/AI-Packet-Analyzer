import { useEffect, useState } from "react";

import { getFindings, getFlowDetail, getFlows, getJob, getSummary, uploadPcap } from "./api/client";
import { FindingsTable } from "./components/FindingsTable";
import { FlowDetailPanel } from "./components/FlowDetailPanel";
import { FlowExplorer } from "./components/FlowExplorer";
import { StatusStrip } from "./components/StatusStrip";
import { SummaryPanel } from "./components/SummaryPanel";
import { UploadPanel } from "./components/UploadPanel";
import type { AnalysisJob, FindingRecord, FlowDetail, FlowListItem, JobSummary } from "./types/api";

export default function App() {
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [summary, setSummary] = useState<JobSummary | null>(null);
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [flows, setFlows] = useState<FlowListItem[]>([]);
  const [selectedFlow, setSelectedFlow] = useState<FlowDetail | null>(null);
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
          getFindings(job.id),
          getFlows(job.id, protocolFilter, search),
        ]);
        if (!cancelled) {
          setSummary(nextSummary);
          setFindings(nextFindings);
          setFlows(nextFlows);
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
  }, [job?.id, protocolFilter, search]);

  async function handleUpload(file: File) {
    try {
      setIsUploading(true);
      setError(null);
      setSelectedFlow(null);
      const createdJob = await uploadPcap(file);
      setJob(createdJob);
      setSummary(null);
      setFindings([]);
      setFlows([]);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Upload failed");
    } finally {
      setIsUploading(false);
    }
  }

  async function handleSelectFlow(flowId: string) {
    if (!job) {
      return;
    }
    try {
      const detail = await getFlowDetail(job.id, flowId);
      setSelectedFlow(detail);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to load flow detail");
    }
  }

  return (
    <main className="app-shell">
      <div className="grid-backdrop" />
      <UploadPanel onUpload={handleUpload} isUploading={isUploading} />
      <StatusStrip job={job} />
      {error ? <div className="error-banner">{error}</div> : null}
      <div className="workspace">
        <div className="workspace-main">
          <SummaryPanel summary={summary} />
          <FindingsTable findings={findings} severityFilter={severityFilter} onSeverityChange={setSeverityFilter} />
          <FlowExplorer
            flows={flows}
            protocol={protocolFilter}
            search={search}
            onProtocolChange={setProtocolFilter}
            onSearchChange={setSearch}
            onSelectFlow={handleSelectFlow}
            selectedFlowId={selectedFlow?.id}
          />
        </div>
        <FlowDetailPanel flow={selectedFlow} />
      </div>
    </main>
  );
}
