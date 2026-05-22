from __future__ import annotations

"""Utility functions that turn raw Scapy reply packets into Python data
structures.  They are used by :pymod:`pla_util_py.api` and may also be handy
when writing your own scripts.
"""

import re
from typing import Any, List, Dict
from scapy.layers.l2 import Ether  # type: ignore
from scapy.packet import Raw  # type: ignore

__all__ = [
    "parse_discover",
    "parse_capabilities",
    "parse_hfid",
    "parse_id_info",
    "parse_discover_list",
    "parse_network_stats",
    "parse_network_info",
    "parse_station_info",
    "parse_qca_sw_version",
    "parse_qca_network_info",
    "parse_qca_network_stats",
]


def _mac_bytes_to_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _payload(pkt: Any) -> bytes:
    if pkt is None:
        raise ValueError("missing packet")
    return bytes(pkt[Raw].load)


def _source_mac(pkt: Any) -> str | None:
    if pkt is None or Ether not in pkt:
        return None
    return pkt[Ether].src.lower()


_QCA_CHIPSET_BY_IDENT = {
    0x001B587C: "QCA7005",
    0x001B589C: "QCA7000",
    0x001B58AC: "QCA7006AQ",
    0x001B58BC: "QCA6411",
    0x001B58DC: "QCA7000",
    0x001B58EC: "QCA6410",
    0x001CFC00: "QCA7420",
    0x001CFCFC: "QCA7420",
    0x001D4C00: "QCA7500",
    0x001D4C0F: "QCA7500",
    0x0E001D1A: "QCA7451",
    0x0F001D1A: "QCA7450",
}

_QCA_CHIPSET_BY_CLASS = {
    0x01: "INT6000",
    0x02: "INT6300",
    0x03: "INT6400/AR7400/AR6405",
    0x06: "PANTHER/LYNX",
    0x07: "QCA7450",
    0x08: "QCA7451",
    0x20: "QCA7420",
    0x21: "QCA6410/QCA6411/QCA7006AQ",
    0x22: "QCA7000/QCA7005",
    0x30: "QCA7500",
}


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------


def parse_discover(pkts: List[Any]) -> List[Dict[str, str]]:
    """Return a list of discovered adapters."""

    adapters: List[Dict[str, str]] = []
    seen = set()
    iface_map = {0: "MII0", 1: "MII1", 2: "PLC", 3: "PLC", 4: "SDR"}

    for pkt in pkts:
        mac = pkt[Ether].src.lower()
        if mac in seen:
            continue
        seen.add(mac)

        payload = bytes(pkt[Raw].load)
        # Confirm this is a discover confirmation: first two bytes 0x02 0x71
        if len(payload) < 12 or payload[0] != 0x02 or payload[1] != 0x71:
            continue
        iface_code = payload[9]
        # HFID starts at byte 11 (offset 12 in Ada, which is 11 here) and runs to end
        hfid = payload[11:].decode("ascii", errors="replace").rstrip("\x00")

        adapters.append({
            "mac": mac,
            "interface": iface_map.get(iface_code, "UNKNOWN"),
            "hfid": hfid,
        })

    return adapters


def parse_capabilities(pkt: Any) -> Dict[str, Any]:
    payload = _payload(pkt)
    if len(payload) < 31:
        raise ValueError("payload too short")

    return {
        "av_version": {0: "1.1", 1: "2.0"}.get(payload[5], "Unknown"),
        "mac_address": _mac_bytes_to_str(payload[6:12]),
        "oui": f"{(payload[12]<<16)|(payload[13]<<8)|payload[14]:06x}",
        "source_mac": _source_mac(pkt),
        "backup_cco": bool(payload[19]),
        "proxy": bool(payload[18]),
        "implementation_version": (payload[28] | (payload[29] << 8)),
    }


def parse_hfid(pkt: Any) -> str:
    payload = bytes(pkt[Raw].load)
    if len(payload) < 14:
        raise ValueError("payload too short")
    return payload[12:].decode("ascii", errors="replace").rstrip("\x00")


def parse_id_info(pkt: Any) -> Dict[str, str]:
    payload = bytes(pkt[Raw].load)
    ver = {0: "1.1", 1: "2.0", 0xFF: "Not HPAV"}.get(payload[9], "Unknown")
    mcs = "MIMO_NOT_SUPPORTED" if ver != "2.0" else {0: "MIMO_NOT_SUPPORTED", 1: "SELECTION_DIVERSITY", 2: "MIMO_WITH_BEAM_FORMING"}.get(payload[11], "UNKNOWN")
    return {"hpav_version": ver, "mcs": mcs}


def parse_network_stats(pkts: list[Any] | Any) -> List[Dict[str, int]]:
    if not isinstance(pkts, list):
        pkts = [pkts]

    combined: Dict[str, Dict[str, int]] = {}

    for pkt in pkts:
        payload = bytes(pkt[Raw].load)
        offset = 10
        while offset + 10 <= len(payload):
            mac = _mac_bytes_to_str(payload[offset : offset + 6])
            to_rate = payload[offset + 6] | ((payload[offset + 7] & 0x07) << 8)
            from_rate = payload[offset + 8] | ((payload[offset + 9] & 0x07) << 8)
            combined[mac] = {"mac": mac, "to_rate": to_rate, "from_rate": from_rate}
            offset += 10

    return list(combined.values())


def parse_discover_list(pkt: Any) -> Dict[str, Any]:
    payload = bytes(pkt[Raw].load)
    station_count = payload[5]
    octets_per_station = 12
    offset = 6
    stations = []
    for _ in range(station_count):
        base = offset
        role_byte = payload[base + 9]
        stations.append({
            "mac": _mac_bytes_to_str(payload[base : base + 6]),
            "tei": payload[base + 6],
            "same_network": payload[base + 7] != 0,
            "snid": payload[base + 8] & 0x0F,
            "cco": (role_byte & 0x20) != 0,
            "pco": (role_byte & 0x40) != 0,
            "bcco": (role_byte & 0x80) != 0,
            "signal_level": payload[base + 10],
        })
        offset += octets_per_station
    return {"stations": stations}


def parse_network_info(pkt: Any) -> List[Dict[str, Any]]:
    payload = bytes(pkt[Raw].load)
    networks = payload[9]
    entries = []
    offset = 10
    for idx in range(networks):
        entry = {
            "nid": int.from_bytes(payload[offset : offset + 7], "little") & 0x3FFFFFFFFFFFF,
            "cco_mac": _mac_bytes_to_str(payload[offset + 10 : offset + 16]),
        }
        entries.append(entry)
        offset += 19
    # backup CCo macs
    for idx in range(networks):
        bcco_start = 10 + 19 * networks + idx * 6
        if bcco_start + 6 <= len(payload):
            entries[idx]["bcco_mac"] = _mac_bytes_to_str(payload[bcco_start : bcco_start + 6])
    return entries


def parse_station_info(pkt: Any) -> Dict[str, Any]:
    payload = bytes(pkt[Raw].load)
    chip_id = int.from_bytes(payload[9:13], "little")
    return {
        "chip_version_id": chip_id,
    }


def parse_qca_sw_version(pkt: Any) -> Dict[str, Any]:
    """Parse a Qualcomm/Atheros VS_SW_VER confirmation."""

    payload = _payload(pkt)
    if len(payload) < 9:
        raise ValueError("payload too short")
    if payload[0] != 0x00 or int.from_bytes(payload[1:3], "little") != 0xA001:
        raise ValueError("not a VS_SW_VER confirmation")

    status = payload[6]
    device_class = payload[7]
    version_length = payload[8]
    version_end = min(len(payload), 9 + version_length)
    version = payload[9:version_end].decode("ascii", errors="replace").rstrip("\x00")

    ident = None
    if len(payload) >= 9 + 254 + 4:
        ident = int.from_bytes(payload[9 + 254 : 9 + 254 + 4], "little")

    chipset = _QCA_CHIPSET_BY_IDENT.get(ident or -1)
    if chipset is None:
        match = re.search(r"\b(QCA[0-9A-Z]+|AR[0-9A-Z]+|INT[0-9A-Z]+)\b", version)
        chipset = match.group(1) if match else _QCA_CHIPSET_BY_CLASS.get(device_class, "UNKNOWN")

    return {
        "backend": "qca",
        "vendor": "Qualcomm Atheros",
        "chipset": chipset,
        "firmware": version,
        "device_class": device_class,
        "ident": ident,
        "status": status,
        "source_mac": _source_mac(pkt),
    }


def _qca_coupling_name(value: int) -> str:
    return "Alternate" if value else "Primary"


def _qca_role_name(role: int) -> str:
    return {0x00: "STA", 0x01: "PROXY_STA", 0x02: "CCO"}.get(role, f"UNKNOWN({role})")


def parse_qca_network_info(pkt: Any) -> Dict[str, Any]:
    """Parse a Qualcomm/Atheros VS_NW_INFO confirmation."""

    payload = _payload(pkt)
    if len(payload) < 12:
        raise ValueError("payload too short")
    if payload[0] != 0x01 or int.from_bytes(payload[1:3], "little") != 0xA039:
        raise ValueError("not a VS_NW_INFO confirmation")

    data_length = int.from_bytes(payload[10:12], "little")
    data = payload[12 : 12 + data_length] if data_length else payload[12:]
    if len(data) < 2:
        raise ValueError("network data too short")

    result: Dict[str, Any] = {
        "source": _source_mac(pkt),
        "sub_version": payload[8],
        "networks": [],
        "stations": [],
    }

    offset = 0
    network_count = data[offset + 1]
    offset += 2

    for _ in range(network_count):
        if offset + 32 > len(data):
            break

        network = {
            "nid": data[offset : offset + 7].hex(":"),
            "snid": data[offset + 9],
            "tei": data[offset + 10],
            "role": _qca_role_name(data[offset + 15]),
            "role_code": data[offset + 15],
            "cco_mac": _mac_bytes_to_str(data[offset + 16 : offset + 22]),
            "cco_tei": data[offset + 22],
            "station_count": data[offset + 26],
            "stations": [],
        }
        offset += 32

        for _ in range(network["station_count"]):
            if offset + 24 > len(data):
                break

            coupling = data[offset + 18]
            station = {
                "mac": _mac_bytes_to_str(data[offset : offset + 6]),
                "tei": data[offset + 6],
                "bda": _mac_bytes_to_str(data[offset + 10 : offset + 16]),
                "to_rate": int.from_bytes(data[offset + 16 : offset + 18], "little"),
                "from_rate": int.from_bytes(data[offset + 20 : offset + 22], "little"),
                "tx_coupling": _qca_coupling_name(coupling & 0x0F),
                "rx_coupling": _qca_coupling_name((coupling >> 4) & 0x0F),
                "role": "CCO" if data[offset + 6] == network["cco_tei"] else "STA",
            }
            network["stations"].append(station)
            result["stations"].append(station)
            offset += 24

        result["networks"].append(network)

    return result


def parse_qca_network_stats(pkt: Any) -> List[Dict[str, Any]]:
    """Return QCA VS_NW_INFO peer rates in the existing stats shape."""

    info = parse_qca_network_info(pkt)
    return [
        {
            "mac": station["mac"],
            "to_rate": station["to_rate"],
            "from_rate": station["from_rate"],
        }
        for station in info["stations"]
    ]
