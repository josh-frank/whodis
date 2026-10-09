#!/usr/bin/env python3
"""Print a domain summary in the terminal.

Usage: python3 whodis.py example.com

Uses RDAP (the structured successor to WHOIS) via the rdap.org bootstrap
redirector, so there is no port-43 parsing and no third-party packages.
"""
import json
import sys
import urllib.request


def fetch(domain):
    req = urllib.request.Request(
        f"https://rdap.org/domain/{domain}",
        headers={"Accept": "application/rdap+json", "User-Agent": "whois-table/1.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def vcard(entity):
    """Flatten an entity's vcardArray into {field: value}."""
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        name, _, _, value = item[0], item[1], item[2], item[3]
        if isinstance(value, list):
            value = ", ".join(v for v in value if v)
        out[name] = value
    return out


def find(entities, role):
    for e in entities or []:
        if role in e.get("roles", []):
            return e
        nested = find(e.get("entities"), role)
        if nested:
            return nested
    return None


def event(data, action):
    for e in data.get("events", []):
        if e.get("eventAction") == action:
            return e.get("eventDate", "")[:10]
    return "-"


def row(label, value):
    print(f"{label}:")
    for v in value if isinstance(value, list) else [value]:
        print(f"{v or '-'}")


def section(title):
    print(f"\n{title}")


def contact_block(entity):
    if not entity:
        print("(not published / redacted)")
        return
    card = vcard(entity)
    if card.get("org"):
        row("Organization", card["org"])
    if card.get("fn"):
        row("Name", card["fn"])
    if card.get("adr"):
        row("Country", card["adr"].split(",")[-1].strip())
    row("Email", card.get("email") or "(redacted)")


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: whodis.py <domain>")
    domain = sys.argv[1].lower().strip()
    try:
        d = fetch(domain)
    except Exception as exc:
        sys.exit(f"lookup failed for {domain}: {exc}")

    print(domain)
    section("Domain Information")
    row("Domain", d.get("ldhName", domain).lower())
    row("Registered On", event(d, "registration"))
    row("Expires On", event(d, "expiration"))
    row("Updated On", event(d, "last changed"))
    row("Status", d.get("status", []))
    row("Name Servers", [ns["ldhName"].lower() for ns in d.get("nameservers", [])])

    entities = d.get("entities", [])

    section("Registrar Information")
    reg = find(entities, "registrar")
    if reg:
        card = vcard(reg)
        row("Registrar", card.get("fn"))
        iana = next((p["identifier"] for p in reg.get("publicIds", [])
                     if "IANA" in p.get("type", "")), None)
        row("IANA ID", iana)
        row("Email", card.get("email"))
        abuse = find(reg.get("entities"), "abuse")
        if abuse:
            a = vcard(abuse)
            row("Abuse Email", a.get("email"))
            row("Abuse Phone", (a.get("tel") or "").replace("tel:", ""))
    else:
        print("(not published)")

    section("Registrant Contact")
    contact_block(find(entities, "registrant"))

    section("Technical Contact")
    contact_block(find(entities, "technical"))


if __name__ == "__main__":
    main()