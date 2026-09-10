#!/usr/bin/env python3
"""
The AI applications this lab governs, and the names the portal knows them by.

Kept in one place so the traffic generator, the classification helper, the
policy builder and the challenge checks can never disagree about what is
supposed to be approved, unapproved, or left alone.

Two identifier spaces matter here and they are not interchangeable:

  * DNS domain   — what the workstation actually resolves, and therefore what
                   the DFP sees and what a block manifests against.
  * Application  — what Infoblox Threat Defense Application Discovery calls
    name           the thing after it has classified those queries. Policy is
                   written against application names, not domains.

A block is enforced per application, but observed per domain. Every script that
verifies enforcement has to cross that boundary, so both names live together
in one record.

Application names are what the portal displays. They are matched
case-insensitively and with a small alias list, because the exact string
Infoblox uses has changed before (Bard -> Google Gemini) and a lab that hard
matches one spelling breaks silently when it changes again.
"""

# --------------------------------------------------------------------------- #
# The AI applications on the company's list
# --------------------------------------------------------------------------- #
# Five tools, one approved and four unapproved, so the split is a real
# decision and not a formality.
#
# Microsoft Copilot was removed. It shares a detection surface with Windows
# Defender on the desktop, and the conflict between the two produced
# unreliable results in the classify and enforce challenges, so it was
# dropped rather than fought.
#
# ChatGPT and OpenAI are listed as two separate applications on purpose, not
# merged. Threat Defense discovers them separately, because chatgpt.com and
# openai.com are different applications to it even though they share a
# vendor, and a participant who only classifies ChatGPT leaves OpenAI sitting
# in Needs Review with no policy covering it. The scenario approves the
# product the business actually sanctioned, ChatGPT, and leaves the vendor's
# other domain, OpenAI, unapproved like everything else. That is worth
# teaching in itself: approving a product does not approve the rest of its
# vendor's estate.

AI_APPLICATIONS = [
    {
        "app": "ChatGPT",
        "domain": "chatgpt.com",
        "vendor": "OpenAI",
        "aliases": ["Chat GPT"],
        "extra_domains": ["chat.openai.com"],
    },
    {
        "app": "OpenAI",
        "domain": "openai.com",
        "vendor": "OpenAI",
        "aliases": ["OpenAI.com"],
        "extra_domains": [],
    },
    {
        "app": "Claude",
        "domain": "claude.ai",
        "vendor": "Anthropic",
        "aliases": ["Anthropic Claude", "Anthropic", "claude"],
        "extra_domains": ["anthropic.com"],
    },
    {
        "app": "Google Gemini",
        "domain": "gemini.google.com",
        "vendor": "Google",
        "aliases": ["Gemini", "Bard", "Google Bard"],
        "extra_domains": ["bard.google.com"],
    },
    {
        "app": "Perplexity",
        "domain": "perplexity.ai",
        "vendor": "Perplexity AI",
        "aliases": ["Perplexity AI", "perplexity"],
        "extra_domains": [],
    },
]

# The application the narrative standardises on. The business picked one
# assistant, and this is it. Everything else, including OpenAI, becomes
# Unapproved.
DEFAULT_APPROVED_APP = "ChatGPT"


# --------------------------------------------------------------------------- #
# Control domain
# --------------------------------------------------------------------------- #
# Must keep resolving from first boot to last check. If this stops working the
# participant has broken DNS rather than configured a policy, and every check
# says so explicitly instead of reporting a block that is really an outage.

CONTROL_DOMAIN = "www.infoblox.com"


# --------------------------------------------------------------------------- #
# Accessors
# --------------------------------------------------------------------------- #

def app_names():
    """Portal application names for every AI tool in the lab."""
    return [entry["app"] for entry in AI_APPLICATIONS]


def primary_domains():
    """One representative domain per application, in brief order."""
    return [entry["domain"] for entry in AI_APPLICATIONS]


def all_domains(include_extra=True):
    """
    Every domain associated with the AI applications.

    The traffic generator wants this wide list: Application Discovery
    classifies on the names it observes, and some applications are only
    recognised once their API or CDN domain has been seen too.
    """
    domains = []
    for entry in AI_APPLICATIONS:
        domains.append(entry["domain"])
        if include_extra:
            domains.extend(entry["extra_domains"])
    return domains


def entry_for_app(name):
    """
    The record for an application, matched on name or alias.

    Case- and space-insensitive, so "google gemini", "Gemini" and "Bard" all
    resolve to the same record.
    """
    key = _normalise(name)
    for entry in AI_APPLICATIONS:
        if _normalise(entry["app"]) == key:
            return entry
        if any(_normalise(alias) == key for alias in entry["aliases"]):
            return entry
    return None


def entry_for_domain(domain):
    """The record that owns a domain, or None."""
    key = domain.lower().strip(".")
    for entry in AI_APPLICATIONS:
        if key == entry["domain"] or key in entry["extra_domains"]:
            return entry
    return None


def domains_for_app(name, include_extra=True):
    """Every domain belonging to one application."""
    entry = entry_for_app(name)
    if not entry:
        return []
    domains = [entry["domain"]]
    if include_extra:
        domains += entry["extra_domains"]
    return domains


def expected_split(approved_app=DEFAULT_APPROVED_APP):
    """
    (approved, unapproved) application names for the target end state.

    The checks use this rather than recomputing the split in three places and
    getting it subtly different in one of them.
    """
    entry = entry_for_app(approved_app)
    approved = entry["app"] if entry else approved_app
    unapproved = [e["app"] for e in AI_APPLICATIONS if e["app"] != approved]
    return approved, unapproved


def _normalise(value):
    return "".join((value or "").lower().split())
