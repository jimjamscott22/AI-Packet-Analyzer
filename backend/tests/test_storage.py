from io import BytesIO
import asyncio

import pytest
from fastapi import UploadFile

from app.services.storage import save_upload


def test_save_upload_rejects_non_pcap():
    upload = UploadFile(filename="not-valid.txt", file=BytesIO(b"hello"))

    with pytest.raises(Exception):
        asyncio.run(save_upload(upload))
