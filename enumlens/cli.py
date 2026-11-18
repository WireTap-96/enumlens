"""Summarize saved Nmap XML locally; this module performs no scanning."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def analyze_xml(xml_text: str) -> dict:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("expected an Nmap XML document with an <nmaprun> root")

    hosts = []
    for host in root.findall("host"):
        status_node = host.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        addresses = [node.get("addr", "") for node in host.findall("address") if node.get("addrtype") in ("ipv4", "ipv6")]
        names = [node.get("name", "") for node in host.findall("./hostnames/hostname") if node.get("name")]
        open_ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            item = {"protocol": port.get("protocol", "unknown"), "port": int(port.get("portid", "0"))}
            if service is not None and service.get("name"):
                item["service"] = service.get("name")
            open_ports.append(item)
        if status == "up" or open_ports or addresses or names:
            hosts.append({"status": status, "addresses": addresses, "hostnames": names, "open_ports": sorted(open_ports, key=lambda x: (x["protocol"], x["port"]))})

    return {
        "hosts_in_report": len(hosts),
        "open_services": sum(len(host["open_ports"]) for host in hosts),
        "hosts": hosts,
        "scope": "Offline report parsing only; no scans or network requests were performed.",
        "caution": "Interpret results only within the authorized scope of the original assessment.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize a saved Nmap XML file from an authorized lab.")
    parser.add_argument("xml_file", type=Path, help="local XML report file; this tool never scans")
    args = parser.parse_args()
    try:
        result = analyze_xml(args.xml_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
