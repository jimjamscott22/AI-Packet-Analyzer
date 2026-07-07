from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException, UploadFile, status

from app.core.config import get_settings


@dataclass
class SavedUpload:
    filename: str
    stored_path: str


async def save_upload(file: UploadFile) -> SavedUpload:
    settings = get_settings()
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only .pcap and .pcapng files are supported")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty")
    if len(data) > settings.max_upload_size_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Uploaded file exceeds size limit")

    stored_path = settings.upload_dir / f"{uuid4()}{suffix}"
    stored_path.write_bytes(data)
    return SavedUpload(filename=file.filename or stored_path.name, stored_path=str(stored_path))
