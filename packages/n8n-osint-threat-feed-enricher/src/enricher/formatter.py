"""Formatters for Obsidian Vault Notes and Telegram/Discord Alerts."""

from __future__ import annotations

from typing import Optional
from enricher.models import ThreatAdvisory, ThreatDigest


def format_obsidian_digest(digest: ThreatDigest, date_str: Optional[str] = None) -> str:
    """Format threat digest into clean Obsidian Daily Note / Threat Intel Zettel."""
    date_val = date_str or digest.generated_at[:10]

    lines = [
        "---",
        f'title: "Threat Intelligence Briefing — {date_val}"',
        'type: "osint-digest"',
        'status: "active"',
        f'created_at: "{digest.generated_at}"',
        f"total_ingested: {digest.total_ingested}",
        f"unique_threats: {digest.unique_count}",
        f"critical_threats: {digest.critical_count}",
        "tags: [threat-intel, cve, osint, security]",
        "---",
        "",
        f"# 🛡️ Threat Intelligence Briefing — {date_val}",
        "",
        f"> **Summary:** Ingested **{digest.total_ingested}** raw security advisories. "
        f"Pruned **{digest.duplicate_count}** duplicates using MinHash LSH. "
        f"Identified **{digest.critical_count}** high-risk / actively exploited vulnerabilities.",
        "",
        "## 🚨 Critical & Actively Exploited Threats",
        "",
    ]

    crit_list = [a for a in digest.advisories if a.is_known_exploited or (a.cvss_score and a.cvss_score >= 8.5)]
    if not crit_list:
        lines.append("*No critical or actively exploited vulnerabilities in this stream.*\n")
    else:
        for adv in crit_list:
            cve_tag = f"`{adv.cve_id}`" if adv.cve_id else "`N/A`"
            cvss_tag = f"**CVSS {adv.cvss_score}**" if adv.cvss_score else "**Severity High**"
            exploited_badge = "🔥 **CISA KEV (Actively Exploited)**" if adv.is_known_exploited else "⚠️ High Severity"
            ransomware_note = f"\n  - 🦠 **Ransomware Campaign:** `{adv.ransomware_campaign}`" if adv.ransomware_campaign else ""

            lines.append(f"### {adv.title}")
            lines.append(f"- **CVE:** {cve_tag} | {cvss_tag} | {exploited_badge}{ransomware_note}")
            lines.append(f"- **Source:** `{adv.source_feed.value}` | **Published:** `{adv.published_at}`")
            lines.append(f"- **Description:** {adv.description}")
            if adv.reference_urls:
                lines.append(f"- **References:** [NVD / Advisory Link]({adv.reference_urls[0]})")
            lines.append("")

    lines.append("## 📋 All Deduplicated Advisories\n")
    lines.append("| CVE | Title | Source | CVSS | Status |")
    lines.append("|---|---|---|:---:|:---:|")
    for a in digest.advisories:
        cve_str = a.cve_id or "N/A"
        title_trunc = (a.title[:55] + "...") if len(a.title) > 55 else a.title
        cvss_str = str(a.cvss_score) if a.cvss_score is not None else "-"
        status = "🔥 Exploited" if a.is_known_exploited else "Monitored"
        lines.append(f"| `{cve_str}` | {title_trunc} | `{a.source_feed.value}` | {cvss_str} | {status} |")

    lines.append("\n---\n*Generated autonomously by [[n8n-osint-threat-feed-enricher]] via local MinHash deduplication.*")
    return "\n".join(lines)


def format_telegram_alert(adv: ThreatAdvisory) -> str:
    """Format single high-priority threat advisory into Telegram Markdown."""
    cve_str = adv.cve_id or "Advisory"
    exploited = "🔥 *ACTIVELY EXPLOITED (CISA KEV)*" if adv.is_known_exploited else "⚠️ *High Threat Advisory*"
    cvss = f"CVSS: `{adv.cvss_score}`" if adv.cvss_score else ""
    ransom = f"\n🦠 *Ransomware:* `{adv.ransomware_campaign}`" if adv.ransomware_campaign else ""

    return (
        f"🚨 *OSINT Threat Alert: {cve_str}*\n"
        f"{exploited} | {cvss}{ransom}\n\n"
        f"📌 *Title:* {adv.title}\n"
        f"📖 *Summary:* {adv.description[:250]}...\n\n"
        f"🔗 [Reference Link]({adv.reference_urls[0] if adv.reference_urls else 'https://nvd.nist.gov/'})"
    )
