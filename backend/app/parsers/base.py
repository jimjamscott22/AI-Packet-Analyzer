from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PacketRecord:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    transport: str
    protocol: str
    length: int
    tcp_flags: str | None = None
    dns: dict[str, str | int | float] = field(default_factory=dict)
    http: dict[str, str | int | float] = field(default_factory=dict)
    tls: dict[str, str | int | float] = field(default_factory=dict)


class PacketParser(ABC):
    @abstractmethod
    def parse(self, file_path: str) -> list[PacketRecord]:
        raise NotImplementedError
