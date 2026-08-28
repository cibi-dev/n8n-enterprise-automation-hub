"""n8n-osint-threat-feed-enricher package."""

from enricher.cache import ThreatFeedCache
from enricher.formatter import format_obsidian_digest, format_telegram_alert
from enricher.minhash import (
    compute_minhash_signature,
    estimate_jaccard_similarity,
    tokenize_shingles,
)
from enricher.models import ThreatAdvisory, ThreatDigest, ThreatFeedSource
from enricher.parsers import (
    compute_content_hash,
    parse_cisa_kev_catalog,
    parse_nvd_cve_feed,
)

__version__ = "0.1.0"

__all__ = [
    "ThreatAdvisory",
    "ThreatDigest",
    "ThreatFeedSource",
    "ThreatFeedCache",
    "compute_minhash_signature",
    "estimate_jaccard_similarity",
    "tokenize_shingles",
    "compute_content_hash",
    "parse_cisa_kev_catalog",
    "parse_nvd_cve_feed",
    "format_obsidian_digest",
    "format_telegram_alert",
]
