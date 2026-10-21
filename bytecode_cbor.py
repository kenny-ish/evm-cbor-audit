#!/usr/bin/env python3
"""Inspect Solidity CBOR metadata trailers in deployed EVM bytecode."""

from __future__ import annotations

import argparse
import json
import urllib.request
from typing import Any


class CborError(ValueError):
    """Raised when a CBOR payload is not supported or is malformed."""


class _CborReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _read_uint(self, additional: int) -> int:
        if additional < 24:
            return additional
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        size = sizes.get(additional)
        if size is None:
            raise CborError("indefinite-length and reserved CBOR values are unsupported")
        end = self.pos + size
        if end > len(self.data):
            raise CborError("CBOR value is truncated")
        value = int.from_bytes(self.data[self.pos:end], "big")
        self.pos = end
        return value

    def read(self) -> Any:
        if self.pos >= len(self.data):
            raise CborError("CBOR value is truncated")
        initial = self.data[self.pos]
        self.pos += 1
        major = initial >> 5
        additional = initial & 0x1F

        if major == 0:
            return self._read_uint(additional)
        if major == 1:
            return -1 - self._read_uint(additional)
        if major in (2, 3):
            length = self._read_uint(additional)
            end = self.pos + length
            if end > len(self.data):
                raise CborError("CBOR byte or text string is truncated")
            raw = self.data[self.pos:end]
            self.pos = end
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CborError("CBOR text string is not UTF-8") from exc
        if major == 4:
            return [self.read() for _ in range(self._read_uint(additional))]
        if major == 5:
            result = {}
            for _ in range(self._read_uint(additional)):
                key = self.read()
                value = self.read()
                result[key] = value
            return result
        if major == 6:
            self._read_uint(additional)
            return self.read()
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            if additional == 23:
                return None
            raise CborError("unsupported CBOR simple or floating-point value")
        raise CborError("unsupported CBOR major type")


def decode_cbor(data: bytes) -> tuple[Any, int]:
    """Decode one definite-length CBOR item and return (value, bytes_used)."""
    reader = _CborReader(data)
    value = reader.read()
    return value, reader.pos


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(_jsonable(key)): _jsonable(item) for key, item in value.items()}
    return value


def _compiler_version(metadata: dict[Any, Any]) -> str | None:
    value = metadata.get("solc")
    if isinstance(value, bytes) and len(value) == 3:
        return f"{value[0]}.{value[1]}.{value[2]}"
    if isinstance(value, str):
        return value
    return None


def parse_metadata_trailer(code: bytes) -> dict[str, Any]:
    """Locate and decode a Solidity CBOR trailer in runtime bytecode."""
    if len(code) < 2:
        return {"status": "no-solidity-cbor", "reason": "bytecode is shorter than two bytes"}

    length = int.from_bytes(code[-2:], "big")
    start = len(code) - 2 - length
    if start < 0:
        return {
            "status": "invalid-solidity-cbor",
            "reason": "trailer length points before the start of bytecode",
            "metadata_length": length,
        }

    payload = code[start:-2]
    try:
        metadata, used = decode_cbor(payload)
    except CborError as exc:
        return {
            "status": "invalid-solidity-cbor",
            "reason": str(exc),
            "metadata_start": start,
            "metadata_length": length,
        }

    if used != len(payload) or not isinstance(metadata, dict):
        return {
            "status": "invalid-solidity-cbor",
            "reason": "trailer is not one complete CBOR map",
            "metadata_start": start,
            "metadata_length": length,
            "bytes_decoded": used,
        }

    return {
        "status": "ok",
        "metadata_start": start,
        "metadata_length": length,
        "compiler": _compiler_version(metadata),
        "metadata": _jsonable(metadata),
    }


def rpc_call(rpc_url: str, method: str, params: list[Any]) -> Any:
    """Make one JSON-RPC request without a third-party client."""
    request_body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode("utf-8")
    request = urllib.request.Request(
        rpc_url,
        data=request_body,
        headers={"Content-Type": "application/json", "User-Agent": "evm-cbor-audit/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        envelope = json.loads(response.read().decode("utf-8"))
    if "error" in envelope:
        raise RuntimeError(str(envelope["error"]))
    return envelope["result"]


def audit_bytecode(code_hex: str) -> dict[str, Any]:
    """Audit a 0x-prefixed bytecode string."""
    if not code_hex.startswith("0x"):
        raise ValueError("bytecode must start with 0x")
    if len(code_hex) % 2:
        raise ValueError("bytecode hex has an odd number of digits")
    try:
        code = bytes.fromhex(code_hex[2:])
    except ValueError as exc:
        raise ValueError("bytecode is not hexadecimal") from exc
    result = {"code_bytes": len(code)}
    result.update(parse_metadata_trailer(code))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode the Solidity CBOR metadata trailer in EVM bytecode."
    )
    parser.add_argument("--rpc-url", help="JSON-RPC endpoint")
    parser.add_argument("--address", help="contract address to inspect")
    parser.add_argument("--block", default="latest", help="block tag or hex block number")
    parser.add_argument("--bytecode", help="offline 0x-prefixed runtime bytecode")
    args = parser.parse_args()

    if args.bytecode is not None:
        result = audit_bytecode(args.bytecode)
        result["source"] = "bytecode"
    elif args.rpc_url and args.address:
        code_hex = rpc_call(args.rpc_url, "eth_getCode", [args.address, args.block])
        result = audit_bytecode(code_hex)
        result.update({"source": "rpc", "address": args.address, "block": args.block})
    else:
        parser.error("use --bytecode, or provide both --rpc-url and --address")
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
