# Preventing Shadow AI — lab automation

Terraform and Python for the Instruqt track **Policies for AI Usage:
Preventing Shadow AI**.

This repository is cloned into the Instruqt shell container at run time by
`track_scripts/setup-shell`. It deploys a NIOS-X host acting as a DNS
Forwarding Proxy plus a Windows desktop into an AWS sandbox, provisions a
Cloud Services Portal tenant for the participant, and verifies each challenge.

> **Repository name.** This repo is still called `nios-rpz-lab` from the
> earlier version of this track, which taught the same lesson using a NIOS
> Grid Master and a Response Policy Zone. The lab now uses Infoblox Threat
> Defense and Application Discovery instead. Nothing depends on the name;
> renaming it means updating `LAB_REPO_URL` in `setup-shell` and the `workdir`
> in each challenge's tab definition.

## What the lab teaches

Which AI tools are in use on a network, who is using them, and how to enforce
an organisational decision about them at the DNS layer — with no endpoint
agent and no change to the network path.

The participant does the work in the Infoblox Portal. This repository builds
the environment that makes it possible and checks the result.

## Architecture

```
Windows desktop  --DNS-->  NIOS-X DFP  --DNS-->  Infoblox Threat Defense
  10.100.0.100              10.100.0.200              (SaaS, per-participant tenant)
```

| Resource | Detail |
|---|---|
| VPC | `10.100.0.0/16`, one public subnet `10.100.0.0/24`, single AZ |
| NIOS-X host | `m5.large`, joins the CSP tenant with a join token in cloud-config, `10.100.0.200` + EIP |
| Windows desktop | `t3.medium`, Windows Server 2022, resolver pinned to the DFP, DoH disabled, `10.100.0.100` + EIP |
| CSP tenant | Allocated from the Sandbox Broker pool, with a portal user, an API key and a join token |

Nothing about the AI policy is created by Terraform or by the setup scripts.
Discovering, classifying and enforcing is the lab.

## Prerequisites

**Instruqt secrets.** All of these are declared in the track's `config.yml`.
Instruqt secrets are per-track: storing a value at the organisation level does
not deliver it to a track that has not listed it.

| Secret | Used for |
|---|---|
| `TF_VAR_windows_admin_password` | Windows Administrator, WinRM and the Guacamole mapping |
| `BROKER_API_TOKEN` | claiming a CSP subtenant from the Sandbox Broker warm pool |
| `INFOBLOX_EMAIL` | CSP admin, for the portal user, API key and join token |
| `INFOBLOX_PASSWORD` | as above |
| `Infoblox_Token` | parent-account token for `POST /v2/sandbox/accounts`; unused on the happy path, kept for direct subtenant creation if the pool runs dry |
| `DEMO_AWS_ACCESS_KEY_ID` | the separate demo account that owns the public DNS zone |
| `DEMO_AWS_SECRET_ACCESS_KEY` | as above |
| `DEMO_HOSTED_ZONE_ID` | the `iracictechguru.com` hosted zone |

This set matches `infoblox-threat-defense-live-event-exchange`, which is the
reference for CSP-based tracks in this organisation.

## Where the CSP tenant comes from

Two mechanisms exist in this estate. This lab uses the first.

**Sandbox Broker (used here).** The Broker maintains a warm pool of
pre-created CSP subtenants. `allocate_sandbox.py` claims one:

```
POST https://api-sandbox-broker.highvelocitynetworking.com/v1/allocate
Authorization: Bearer $BROKER_API_TOKEN
X-Instruqt-Sandbox-ID: <participant id>
```

It creates nothing — it hands over a tenant that already exists, in about a
second. `201` means one was taken from the pool, `200` means this participant
already had one (allocation is idempotent), and `409` means the pool is
exhausted, which is fatal because retrying cannot conjure a subtenant.
Deallocation marks it for deletion and a background worker tears it down.

**Direct creation (not used here).** `POST /v2/sandbox/accounts` on the CSP
creates a real subtenant under the parent account, authenticated with
`Authorization: token $Infoblox_Token`:

```json
{ "name": "<participant id>", "state": "active",
  "admin_user": { "email": "...", "name": "<participant id>" } }
```

It returns `result.id` (`identity/accounts/<uuid>`) and
`result.admin_user.account_id`. This is what
`secure-ai-infoblox/scripts/create_subtenant_infoblox.py` does, and
`DELETE /v2/sandbox/accounts/{id}` removes it.

It is slower — creation needs propagation time, which is why the tracks using
it sleep for two minutes afterwards — and it can fail under load, so the
Broker is preferred. `Infoblox_Token` is declared anyway so that this path is
available without a secrets change if the pool is ever empty.

In **both** cases the tenant arrives with no interactive user. The
participant's portal login is created separately, inside the tenant, by
`provision_tenant.py` via `POST /v2/users` using a JWT that has been
account-switched into the subtenant.

**Subscription.** Application Discovery requires **Infoblox Threat Defense
Advanced**. If the sandbox pool is provisioned at a lower tier, challenges 2
and 3 cannot work — see Troubleshooting.

## Setup order

The order is not arbitrary; each step needs the one before it.

1. `allocate_sandbox.py` — claim a CSP subtenant, write `sandbox_id.txt`
2. `provision_tenant.py` — portal user, API key, **join token**
3. `terraform apply` — needs the join token as `TF_VAR_infoblox_join_token`
4. `setup_dns.py` — publish `<participant>-desktop.<zone>` for Guacamole
5. `setup_dfp.py` — wait for host registration, then enable the DFP service
6. `generate_ai_traffic.py --seed` — give Application Discovery something to show

Step 5 cannot be done by Terraform: the DFP service is created against the
host's pool, and the pool does not exist until the host has registered.

Step 6 runs at setup because Threat Defense has to observe, aggregate and
classify queries before an application appears under *Needs Review*, and
Infoblox does not document how long that takes. Seeding means the participant
opens a populated report instead of waiting on an unquantified pipeline.

## Layout

```
terraform/
  main.tf                     key pair, then three modules
  variables.tf                includes infoblox_join_token (sensitive, no default)
  outputs.tf                  dfp_*, desktop_*, vpc_id, subnet_id
  modules/
    vpc/                      VPC, subnet, IGW, route table, 2 security groups
    niosx-dfp/                NIOS-X host, join token in #cloud-config
    desktop/                  Windows desktop
      templates/desktop-init.ps1.tpl

scripts/
  csp_api.py                  shared CSP client: JWT + API key auth, endpoint discovery
  domains.py                  the five AI applications, their domains and portal names

  allocate_sandbox.py         claim a sandbox from the Broker pool
  deallocate_sandbox.py       hand it back
  provision_tenant.py         portal user + API key + join token
  setup_dfp.py                wait for the host, enable the DFP service
  setup_dns.py                publish the desktop's public DNS name
  cleanup_dns_records.py      remove it again

  app_discovery.py            list and classify discovered applications
  security_policy.py          read and edit the policy's application filter rules
  generate_ai_traffic.py      drive AI lookups from the desktop
  desktop_dns.py              DNS lookups on the desktop, over WinRM

  verify_lab.py               the four challenge checks
  discover_td_api.py          find the real Application Discovery endpoints
  preflight.sh                run before every push
```

## Before you push

```bash
./scripts/preflight.sh
```

It runs `terraform fmt`, `init`, and — the one that matters — `validate`, which
evaluates every `templatefile()` call and every provider-side attribute
validation. It then renders the desktop template and checks the result is
valid, that variables were substituted, and that DoH is still disabled. It
also warns about uncommitted or unpushed work, because the track clones this
repo from GitHub and a fix that only exists on disk will not apply.

Three failures reached a live lab start before this existed: an em dash in a
security-group description, a `${...}` inside a comment in a `.tpl` file, and a
fix that was never committed. `terraform fmt` catches none of them.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `setup_dfp.py` times out waiting for the host | The join token was rejected or the instance has no outbound 443 to `csp.infoblox.com`. Check the instance booted and `provision_tenant.py` produced a token. |
| Desktop resolves nothing, `port53_listening` false | The DFP service is not running. `python3 setup_dfp.py --status`. |
| Application Discovery is empty | Either not enough traffic yet (`generate_ai_traffic.py --rounds 3`) or the tenant is not Threat Defense **Advanced**, which the feature requires. |
| `EndpointNotFound` from `app_discovery.py` | The Application Discovery API paths are unconfirmed — see below. Run `python3 discover_td_api.py`. |
| Blocks do not take effect | Rule order. `python3 security_policy.py show` — Block must sit above Allow. |
| Everything is blocked, including the approved tool | The Allow rule is missing or below the Block rule. Same command. |

### The unconfirmed API

Application Discovery is absent from the published Infoblox API documentation.
The Threat Defense API guide covers `Atcfw`, `Atcep`, `Atcdfp`, `Tdlad`,
`TIDEDossier` and `TIDEData`, none of which documents application approval, and
`/api/atcfw/v1/openapi.json` returns 401 without credentials.

So `app_discovery.py` carries **candidate path lists** resolved against the
live tenant by `CspSession.discover()` rather than hardcoded URLs. If none
match, the error names every path tried and what each returned.

To resolve this properly, run against a real tenant:

```bash
python3 discover_td_api.py           # spec pass + probe pass
python3 discover_td_api.py --spec    # pull the OpenAPI document and grep it
```

With a valid API key the CSP serves its own OpenAPI document, which lists every
path it implements. Put the winning paths first in the candidate lists in
`app_discovery.py` and the guesswork is gone.

Until then, the classify check degrades to a warning rather than failing a
participant who did the work correctly in the portal. Set
`LAB_STRICT_CHECKS=1` to make it fatal while you are fixing the lists.

The enforcement check does not depend on any of this: it asserts on DNS
answers from the desktop, which is the behaviour that actually matters.
