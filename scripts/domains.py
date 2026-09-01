#!/usr/bin/env python3
"""
The domain sets this lab enforces on, and the names of the RPZ objects.

Kept in one place so the configure, verify and check paths can never disagree
about what is supposed to be blocked.

Why this list is hand-maintained: there is no managed Infoblox RPZ feed that
carries generative-AI domains for NIOS. The published NIOS feed catalogue is
Base, Base IP, High/Medium/Low Risk, Informational plus special-purpose feeds
such as cryptocurrency and public-doh. Generative AI is an *application*
classification, and application-level control lives in Infoblox Threat Defense
Cloud, not in a NIOS-consumable feed. A local RPZ is therefore the mechanism —
see decision 1 in the lab brief.
"""

# --------------------------------------------------------------------------- #
# RPZ object naming
# --------------------------------------------------------------------------- #

RPZ_ZONE_FQDN = "genai-block.rpz.local"
RPZ_ZONE_COMMENT = "Local RPZ blocking public generative AI services"
DNS_VIEW = "default"

# NIOS represents a "Block Domain Name (No Such Domain)" rule as a
# record:rpz:cname whose canonical is the empty string.
BLOCK_NXDOMAIN_CANONICAL = ""

# The domain the participant allow-lists in the final challenge. The narrative
# is that the business standardised on one approved assistant, so this is the
# same domain they watched get blocked earlier.
PASSTHRU_DEFAULT_DOMAIN = "claude.ai"


# --------------------------------------------------------------------------- #
# Generative AI services
# --------------------------------------------------------------------------- #
# Apex domains only. configure_rpz.py adds a matching *.<domain> wildcard rule
# for each, so subdomains such as chat.openai.com are covered without listing
# them individually.

GENAI_DOMAINS = [
    {"domain": "claude.ai", "vendor": "Anthropic"},
    {"domain": "anthropic.com", "vendor": "Anthropic"},
    {"domain": "chatgpt.com", "vendor": "OpenAI"},
    {"domain": "openai.com", "vendor": "OpenAI"},
    {"domain": "gemini.google.com", "vendor": "Google"},
    {"domain": "bard.google.com", "vendor": "Google"},
    {"domain": "copilot.microsoft.com", "vendor": "Microsoft"},
    {"domain": "perplexity.ai", "vendor": "Perplexity"},
    {"domain": "grok.com", "vendor": "xAI"},
    {"domain": "x.ai", "vendor": "xAI"},
    {"domain": "mistral.ai", "vendor": "Mistral"},
    {"domain": "deepseek.com", "vendor": "DeepSeek"},
    {"domain": "huggingface.co", "vendor": "Hugging Face"},
    {"domain": "poe.com", "vendor": "Quora"},
    {"domain": "midjourney.com", "vendor": "Midjourney"},
]


# --------------------------------------------------------------------------- #
# DNS-over-HTTPS bootstrap names
# --------------------------------------------------------------------------- #
# A browser that resolves over DoH never asks NIOS, so the RPZ looks broken.
# The desktop's Edge and Windows DNS client both have DoH switched off at boot
# (see modules/desktop/templates/desktop-init.ps1.tpl), and TCP/UDP 853 is
# excluded from the desktop's egress rules. These rules are the third layer:
# if something re-enables DoH, it cannot resolve its own resolver.
#
# This mirrors what the managed public-doh.rpz.infoblox.local feed does for
# customers with a Threat Defense subscription.

DOH_BOOTSTRAP_DOMAINS = [
    {"domain": "cloudflare-dns.com", "vendor": "Cloudflare DoH"},
    {"domain": "mozilla.cloudflare-dns.com", "vendor": "Cloudflare DoH (Firefox)"},
    {"domain": "chrome.cloudflare-dns.com", "vendor": "Cloudflare DoH (Chrome)"},
    {"domain": "dns.google", "vendor": "Google DoH"},
    {"domain": "dns.quad9.net", "vendor": "Quad9 DoH"},
    {"domain": "doh.opendns.com", "vendor": "OpenDNS DoH"},
]


# --------------------------------------------------------------------------- #
# Control domain
# --------------------------------------------------------------------------- #
# Must keep resolving throughout. If this stops working the participant has
# broken recursion rather than configured a policy, and the checks say so
# instead of reporting a phantom success.

CONTROL_DOMAIN = "www.infoblox.com"


# --------------------------------------------------------------------------- #
# Accessors
# --------------------------------------------------------------------------- #

def genai_domains():
    """Apex generative-AI domains, as plain strings."""
    return [entry["domain"] for entry in GENAI_DOMAINS]


def doh_domains():
    """Apex DoH bootstrap domains, as plain strings."""
    return [entry["domain"] for entry in DOH_BOOTSTRAP_DOMAINS]


def all_blocked_domains(include_doh=True):
    """Every apex domain the lab expects to be blocked."""
    domains = genai_domains()
    if include_doh:
        domains += doh_domains()
    return domains


def rule_names(domain, zone=RPZ_ZONE_FQDN):
    """
    The two RPZ record names covering a domain and everything under it.

    NIOS names an RPZ rule <target>.<rpz zone>, so a rule for claude.ai in
    genai-block.rpz.local is called claude.ai.genai-block.rpz.local.
    """
    return [f"{domain}.{zone}", f"*.{domain}.{zone}"]


def vendor_for(domain):
    """Human-readable owner of a domain, for log lines."""
    for entry in GENAI_DOMAINS + DOH_BOOTSTRAP_DOMAINS:
        if entry["domain"] == domain:
            return entry["vendor"]
    return "unknown"
