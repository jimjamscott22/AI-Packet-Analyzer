# 🧠 AI Packet Analyzer (Wireshark + LLM hybrid) 

### What it does: 

- Ingests .pcap files (or live tcpdump) 
- Extracts flows (HTTP, DNS, TLS) 
- Sends summaries to an LLM 

#### Outputs: 
- “This looks like DNS tunneling” 
- “Possible C2 beaconing pattern” 
- “Normal traffic” 

### Stack: 
- Backend: FastAPI 
- Parsing: pyshark or scapy 
- Frontend: React dashboard 

**Bonus: plug into your Raspberry Pi network**