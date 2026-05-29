"""
guardian kb — knowledge base maintenance.

Provides a small Typer app with three subcommands:

    guardian kb status         # show row counts per kind
    guardian kb seed           # seed with bundled sample corpora (offline)
    guardian kb update --kind  # refresh from upstream feeds (network)
    guardian kb query "text"   # ad-hoc search

The retrieval path is exercised by analyst grounding directly — this CLI
is for humans wanting to inspect or rebuild the local index. We make
``status`` and ``seed`` work fully offline so air-gapped engagements can
still benefit from the small bundled corpus shipped under
``data/kb_seed/``.

Network fetches are explicit and gated behind ``--accept-network``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from core.knowledge_base import KBEntry, KnowledgeBase, hits_to_prompt_block

kb_app = typer.Typer(help="Knowledge base maintenance.")
console = Console()


# ── status ───────────────────────────────────────────────────────────────────


@kb_app.command("status")
def status_cmd() -> None:
    """Print row counts per corpus kind."""
    kb = KnowledgeBase()
    stats = kb.stats()
    if not stats:
        console.print("[yellow]KB is empty[/yellow] — run [bold]guardian kb seed[/bold] to bootstrap.")
        raise typer.Exit(0)

    table = Table(title="Guardian KB — corpus status")
    table.add_column("Kind", style="cyan")
    table.add_column("Rows", justify="right", style="green")
    for kind in sorted(stats.keys()):
        table.add_row(kind, str(stats[kind]))
    console.print(table)
    console.print(f"[dim]Path:[/dim] {kb.path}")


# ── seed ─────────────────────────────────────────────────────────────────────


def _seed_entries() -> List[KBEntry]:
    """Bundled offline seed — small but covers the ten most common
    nuclei-template-detected vulns. Useful for first-run validation
    before the operator pulls full feeds.
    """
    return [
        KBEntry(
            id="CVE-2021-44228", kind="cve",
            title="Apache Log4j Remote Code Execution (Log4Shell)",
            summary="Log4j2 <2.15 evaluates JNDI lookups in user-controlled input, enabling unauthenticated RCE.",
            severity="critical", cvss=10.0, cwe="CWE-502",
            refs=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            updated="2021-12-10",
        ),
        KBEntry(
            id="CVE-2017-5638", kind="cve",
            title="Apache Struts2 OGNL Injection",
            summary="Jakarta multipart parser in Struts 2 mishandles Content-Type, enabling remote OGNL injection (Equifax breach).",
            severity="critical", cvss=10.0, cwe="CWE-20",
        ),
        KBEntry(
            id="CVE-2014-0160", kind="cve",
            title="OpenSSL Heartbleed",
            summary="OpenSSL TLS heartbeat extension reads beyond buffer, leaking up to 64KB of process memory.",
            severity="high", cvss=7.5, cwe="CWE-125",
        ),
        KBEntry(
            id="CVE-2021-26855", kind="cve",
            title="Microsoft Exchange ProxyLogon SSRF",
            summary="Pre-auth SSRF in Exchange Server CAS, chained with CVE-2021-27065 for RCE as SYSTEM.",
            severity="critical", cvss=9.1, cwe="CWE-918",
        ),
        KBEntry(
            id="CVE-2018-7600", kind="cve",
            title="Drupalgeddon2 — Drupal Render Array RCE",
            summary="Form API renders #-prefixed keys; attacker injects render-time PHP callable.",
            severity="critical", cvss=9.8, cwe="CWE-20",
        ),
        KBEntry(
            id="CVE-2020-1472", kind="cve",
            title="Zerologon — Netlogon Privilege Escalation",
            summary="Netlogon authentication uses zeroed IV in AES-CFB8, allowing DC compromise from network.",
            severity="critical", cvss=10.0, cwe="CWE-330",
        ),
        # CWE
        KBEntry(
            id="CWE-79", kind="cwe",
            title="Cross-site Scripting (XSS)",
            summary="Improper neutralization of input during webpage generation. Reflected, stored, DOM variants.",
            severity="medium",
        ),
        KBEntry(
            id="CWE-89", kind="cwe",
            title="SQL Injection",
            summary="Improper neutralization of special elements used in SQL command. Often UNION-based or boolean-blind.",
            severity="high",
        ),
        KBEntry(
            id="CWE-22", kind="cwe",
            title="Path Traversal",
            summary="Use of '..' sequences to escape intended directory. Affects file-read endpoints.",
            severity="high",
        ),
        KBEntry(
            id="CWE-918", kind="cwe",
            title="Server-Side Request Forgery (SSRF)",
            summary="Server fetches attacker-controlled URL — pivots to internal services, cloud metadata.",
            severity="high",
        ),
        KBEntry(
            id="CWE-502", kind="cwe",
            title="Deserialization of Untrusted Data",
            summary="Reconstructing objects from attacker bytes — gadget chains lead to RCE in Java/.NET/PHP/Python.",
            severity="critical",
        ),
        # MITRE ATT&CK
        KBEntry(
            id="T1190", kind="attck",
            title="Exploit Public-Facing Application",
            summary="Initial access via vulnerability in internet-facing service. Maps to CVEs found by recon scanners.",
            severity="high",
        ),
        KBEntry(
            id="T1133", kind="attck",
            title="External Remote Services",
            summary="Use of legitimate remote services (VPN, RDP, SSH) for initial access via stolen creds.",
            severity="medium",
        ),
        KBEntry(
            id="T1078", kind="attck",
            title="Valid Accounts",
            summary="Use of compromised credentials. Common defense bypass; pairs with credential dumping.",
            severity="medium",
        ),
        KBEntry(
            id="T1003", kind="attck",
            title="OS Credential Dumping",
            summary="Extract credentials from LSASS, SAM, NTDS.dit, /etc/shadow.",
            severity="high",
        ),
    ]


@kb_app.command("seed")
def seed_cmd() -> None:
    """Insert the bundled offline seed corpus."""
    kb = KnowledgeBase()
    n = kb.upsert(_seed_entries())
    console.print(f"[green]Seeded[/green] {n} entries into {kb.path}")


# ── update ───────────────────────────────────────────────────────────────────


@kb_app.command("update")
def update_cmd(
    kind: str = typer.Option(..., help="Corpus to refresh: cve | cwe | attck | template"),
    accept_network: bool = typer.Option(
        False, "--accept-network",
        help="Required for network fetches (NVD JSON, MITRE STIX, etc.)",
    ),
    file: Optional[Path] = typer.Option(
        None, "--file",
        help="Path to a local JSON file to ingest instead of fetching upstream.",
    ),
) -> None:
    """Pull a fresh corpus from upstream feeds.

    The network path is intentionally minimal — it accepts a file you've
    already downloaded. Air-gapped operators stay fully offline; everyone
    else uses ``curl`` or ``wget`` outside Guardian. We don't take
    on the responsibility of mirroring NVD / MITRE inside the CLI.
    """
    if file is None:
        if not accept_network:
            console.print(
                "[red]Refusing to fetch without --accept-network[/red]. "
                "Pass --file <path> for offline ingestion."
            )
            raise typer.Exit(1)
        console.print(
            "[yellow]Network corpus fetch is not bundled.[/yellow] "
            "Download the feed manually and re-run with --file <path>.\n"
            "Pointers:\n"
            "  CVE:  https://nvd.nist.gov/vuln/data-feeds#JSON_FEED\n"
            "  CWE:  https://cwe.mitre.org/data/csv/2000.csv.zip\n"
            "  ATT&CK: https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
        )
        raise typer.Exit(2)

    if not file.exists():
        console.print(f"[red]File not found:[/red] {file}")
        raise typer.Exit(1)

    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]Failed to parse {file}:[/red] {exc}")
        raise typer.Exit(1) from exc

    entries = _normalize_payload(payload, kind)
    kb = KnowledgeBase()
    n = kb.upsert(entries)
    console.print(f"[green]Ingested[/green] {n} entries (kind={kind}) from {file}")


def _normalize_payload(payload: object, kind: str) -> List[KBEntry]:
    """Loose adapter — accepts a few common shapes:

      * ``{"items": [...]}``
      * top-level list
      * NVD-style ``{"CVE_Items": [...]}``

    Each item is then filtered for the minimum fields we need: id + title.
    Missing fields default sanely. We don't try to be exhaustive — a
    one-shot adapter is the operator's responsibility for now.
    """
    items: List[dict] = []
    if isinstance(payload, list):
        items = [x for x in payload if isinstance(x, dict)]
    elif isinstance(payload, dict):
        for key in ("items", "CVE_Items", "objects", "entries"):
            if key in payload and isinstance(payload[key], list):
                items = [x for x in payload[key] if isinstance(x, dict)]
                break
        if not items:
            # Maybe a single object — wrap it.
            items = [payload]

    entries: List[KBEntry] = []
    for item in items:
        eid = (
            item.get("id")
            or item.get("cve_id")
            or item.get("CVE_ID")
            or item.get("name")
            or ""
        )
        if not eid:
            continue
        title = (
            item.get("title")
            or item.get("name")
            or item.get("summary", "")[:120]
            or eid
        )
        summary = item.get("summary") or item.get("description") or ""
        if isinstance(summary, list):
            summary = " ".join(str(s) for s in summary)
        cvss = item.get("cvss") or item.get("baseScore")
        try:
            cvss_val = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss_val = None
        refs = item.get("refs") or item.get("references") or []
        if not isinstance(refs, list):
            refs = []

        entries.append(KBEntry(
            id=str(eid),
            kind=kind,
            title=str(title)[:500],
            summary=str(summary)[:5000],
            severity=str(item.get("severity") or "unknown").lower(),
            cvss=cvss_val,
            cwe=str(item.get("cwe") or ""),
            refs=[str(r) for r in refs[:20]],
            updated=str(item.get("updated") or item.get("publishedDate") or ""),
        ))
    return entries


# ── query ────────────────────────────────────────────────────────────────────


@kb_app.command("query")
def query_cmd(
    text: str = typer.Argument(..., help="Free-text query — words OR'd into FTS5."),
    k: int = typer.Option(5, "--top", "-k", help="Number of hits."),
    kind: Optional[str] = typer.Option(None, help="Restrict to one kind."),
    show_prompt: bool = typer.Option(
        False, "--prompt", help="Render hits as the prompt-block the analyst would see.",
    ),
) -> None:
    """Ad-hoc retrieval — useful for sanity-checking the index."""
    kb = KnowledgeBase()
    hits = kb.query(text, k=k, kind=kind)
    if not hits:
        console.print("[yellow]No matches.[/yellow]")
        raise typer.Exit(0)

    if show_prompt:
        console.print(hits_to_prompt_block(hits))
        return

    table = Table(title=f"Guardian KB — top {len(hits)} for '{text}'")
    table.add_column("Score", justify="right", style="green")
    table.add_column("ID", style="cyan")
    table.add_column("Kind", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Title")
    for hit in hits:
        table.add_row(
            f"{hit.score:.2f}",
            hit.entry.id,
            hit.entry.kind,
            hit.entry.severity,
            hit.entry.title[:70],
        )
    console.print(table)
