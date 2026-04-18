from app.parsers.scapy_parser import _parse_tls_payload


def test_parse_tls_payload_extracts_client_hello_metadata():
    payload = _build_client_hello_payload(sni="example.com", alpn_protocols=["h2"])

    parsed = _parse_tls_payload(payload)

    assert parsed["looks_like_tls"] is True
    assert parsed["record_version"] == "3.1"
    assert parsed["handshake_type"] == "client_hello"
    assert parsed["client_version"] == "3.3"
    assert parsed["sni"] == "example.com"
    assert parsed["alpn_protocols"] == ["h2"]
    assert parsed["cipher_suites_sample"] == ["0x1301", "0x1302"]
    assert parsed["session_id_length"] == 0
    assert parsed["ja3_like_fingerprint"]


def test_parse_tls_payload_handles_visible_tls_without_sni():
    payload = _build_client_hello_payload(sni=None, alpn_protocols=[])

    parsed = _parse_tls_payload(payload)

    assert parsed["looks_like_tls"] is True
    assert parsed["handshake_type"] == "client_hello"
    assert parsed.get("sni") is None
    assert parsed["alpn_protocols"] == []


def test_parse_tls_payload_tolerates_truncated_handshake():
    parsed = _parse_tls_payload(b"\x16\x03\x01\x00\x20\x01\x00")

    assert parsed["looks_like_tls"] is True
    assert parsed["record_version"] == "3.1"
    assert "handshake_type" not in parsed or parsed["handshake_type"] == "client_hello"


def _build_client_hello_payload(*, sni: str | None, alpn_protocols: list[str]) -> bytes:
    cipher_suites = b"\x13\x01\x13\x02"
    body = bytearray()
    body.extend(b"\x03\x03")
    body.extend(bytes(range(32)))
    body.append(0)
    body.extend(len(cipher_suites).to_bytes(2, "big"))
    body.extend(cipher_suites)
    body.extend(b"\x01\x00")

    extensions = bytearray()
    if sni:
        host = sni.encode("ascii")
        server_name = b"\x00" + len(host).to_bytes(2, "big") + host
        server_name_list = len(server_name).to_bytes(2, "big") + server_name
        extensions.extend((0).to_bytes(2, "big"))
        extensions.extend(len(server_name_list).to_bytes(2, "big"))
        extensions.extend(server_name_list)

    if alpn_protocols:
        encoded = bytearray()
        for protocol in alpn_protocols:
            data = protocol.encode("ascii")
            encoded.append(len(data))
            encoded.extend(data)
        alpn_body = len(encoded).to_bytes(2, "big") + encoded
        extensions.extend((16).to_bytes(2, "big"))
        extensions.extend(len(alpn_body).to_bytes(2, "big"))
        extensions.extend(alpn_body)

    supported_groups = b"\x00\x04\x00\x1d\x00\x17"
    extensions.extend((10).to_bytes(2, "big"))
    extensions.extend(len(supported_groups).to_bytes(2, "big"))
    extensions.extend(supported_groups)

    body.extend(len(extensions).to_bytes(2, "big"))
    body.extend(extensions)

    handshake = bytearray()
    handshake.append(1)
    handshake.extend(len(body).to_bytes(3, "big"))
    handshake.extend(body)

    record = bytearray()
    record.extend(b"\x16\x03\x01")
    record.extend(len(handshake).to_bytes(2, "big"))
    record.extend(handshake)
    return bytes(record)
