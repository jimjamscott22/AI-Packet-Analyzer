import { useState } from "react";

interface UploadPanelProps {
  onUpload: (file: File) => Promise<void>;
  isUploading: boolean;
}

export function UploadPanel({ onUpload, isUploading }: UploadPanelProps) {
  const [dragging, setDragging] = useState(false);

  async function submitFile(file: File | null) {
    if (!file || isUploading) {
      return;
    }
    await onUpload(file);
  }

  return (
    <section className="upload-panel">
      <div className="section-label">PCAP Ingestion</div>
      <h1>Packet analysis workspace</h1>
      <p>
        Upload a capture file to extract flows, score suspicious patterns, and optionally enrich the top anomalies
        with an LLM review.
      </p>
      <label
        className={`dropzone ${dragging ? "is-dragging" : ""}`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={async (event) => {
          event.preventDefault();
          setDragging(false);
          await submitFile(event.dataTransfer.files.item(0));
        }}
      >
        <input
          type="file"
          accept=".pcap,.pcapng"
          onChange={async (event) => {
            await submitFile(event.target.files?.item(0) ?? null);
          }}
        />
        <div>
          <strong>{isUploading ? "Uploading capture..." : "Drop a .pcap here"}</strong>
          <span>Offline PCAP analysis only in v1. Headers and metadata are processed, not full payloads.</span>
        </div>
      </label>
    </section>
  );
}
