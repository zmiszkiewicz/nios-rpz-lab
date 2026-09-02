# nios-rpz-lab

Terraform and Python backing the Instruqt track **Blocking Generative AI with
NIOS Response Policy Zones**.

Published at **<https://github.com/zmiszkiewicz/nios-rpz-lab>** and cloned
anonymously into the Instruqt shell container at track start by
`track_scripts/setup-shell`. It deploys a vNIOS Grid Master, a Windows
desktop and an unmanaged Linux host into an AWS sandbox, and provides the WAPI
tooling the challenge checks use to verify the participant's work.

To point a track at a fork or a branch without editing `setup-shell`, set
`LAB_REPO_URL` or `LAB_REPO_REF` in the environment.

---

## What gets deployed

One AWS region, three instances, roughly **$0.28/hour** in eu-central-1.

| Resource | Detail |
|---|---|
| VPC | `10.100.0.0/16`, one public subnet `10.100.0.0/24`, IGW, route table |
| NIOS Grid Master | `m5.xlarge`, privately shared vNIOS AMI, MGMT `10.100.0.10`, LAN1 `10.100.0.11` + EIP |
| Windows desktop | `t3.medium`, Windows Server 2022, `10.100.0.110` + EIP, resolver pinned to LAN1 |
| Unmanaged host | `t3.micro`, Ubuntu 22.04, `10.100.0.120` + EIP, resolver pinned to **8.8.8.8** — bypasses the RPZ on purpose |
| Security groups | One per role — see [Security posture](#security-posture) |

Nothing about the RPZ itself is created by Terraform. Building it is the lab.

## Prerequisites

- An AWS account the Instruqt sandbox can assume, with EC2, VPC and EIP quota
  for three instances and three Elastic IPs.
- **A privately shared Infoblox vNIOS AMI in your target region.** Not the AWS
  Marketplace listing — the lab defaults to the same privately shared image
  `tech-summit-security-niosx` uses in eu-central-1, so in the normal case there
  is nothing to do. To use a different one, find it with:
  ```bash
  aws ec2 describe-images --region eu-central-1 --owners <infoblox-account-id> \
    --filters "Name=name,Values=*nios*" --query 'Images[].[ImageId,Name]' --output table
  ```
- A **DNS Firewall (RPZ) entitlement**, granted by the `rpz` token in
  `nios_temp_license`. See [Troubleshooting](#the-rpz-licence).
- A Route 53 hosted zone in a second, long-lived AWS account for the
  per-participant public names. This mirrors the `DEMO_*` split every other lab
  here uses: lab resources go in the throwaway sandbox, public DNS lives
  somewhere stable.
- Terraform **1.10.5** — the version `setup-shell` installs and every
  `*-live-exchange` track in this org pins.
- Python 3 with `requests`, `boto3`, `pywinrm` (`scripts/requirements.txt`).

## Required variables and secrets

### Instruqt secrets

All four already exist on the other tracks in this organisation — nothing new
needs provisioning.

| Secret | Purpose |
|---|---|
| `TF_VAR_windows_admin_password` | Windows Administrator password; also used for the NIOS `admin` account and by the Guacamole mapping |
| `DEMO_AWS_ACCESS_KEY_ID` | Credentials for the account owning the public DNS zone |
| `DEMO_AWS_SECRET_ACCESS_KEY` | " |
| `DEMO_HOSTED_ZONE_ID` | Route 53 hosted zone ID for the per-participant names |

| Optional secret | Purpose |
|---|---|
| `NIOS_AMI_ID` | Overrides `var.nios_ami_id` at runtime. Only worth setting to test a rotated image without a commit. |

This track does **not** allocate an Infoblox CSP sandbox tenant, so
`Infoblox_Token`, `INFOBLOX_EMAIL`, `INFOBLOX_PASSWORD` and `BROKER_API_TOKEN`
are not required. The whole scenario runs on the Grid Master, and dropping the
tenant allocation removes about eight minutes of propagation sleeps from setup.

### Terraform variables

Everything has a default except the two passwords. See
`terraform/terraform.tfvars.example` for the full set.

| Variable | Set from |
|---|---|
| `windows_admin_password` | `TF_VAR_windows_admin_password` |
| `nios_admin_password` | Defaults to `TF_VAR_windows_admin_password` in `setup-shell` |
| `nios_ami_id` | Defaults to `ami-0f223da0ec214a840` (see below) |

### Values to confirm before go-live

| Value | Where | Why it needs confirming |
|---|---|---|
| `nios_ami_id` | `terraform/variables.tf` | Defaults to the vNIOS Grid Master image `tech-summit-security-niosx` uses in eu-central-1. Confirm it is still shared with your account and has not been rotated. |
| `nios_temp_license` | `terraform/variables.tf` | Carries the `rpz` token for DNS Firewall. Worth a `show license` on the first boot, as with any new licence combination. |
| `LAB_DNS_ZONE` | `scripts/setup_dns.py`, `track_scripts/setup-rdpclient` | Defaults to `iracictechguru.com`, matching the other labs. |
| AWS region | `terraform/variables.tf` | Defaults to `eu-central-1`; the AMI is region-specific and must exist there. |

## Layout

```
terraform/
  main.tf                     root — key pair, module wiring
  variables.tf                all inputs, three of them required
  outputs.tf                  consumed by setup-shell via `terraform output -raw`
  providers.tf                aws ~> 5.20, pinned to Terraform ~> 1.10
  terraform.tfvars.example
  modules/
    vpc/                      VPC, subnet, IGW, routing, all three security groups
    nios-gm/                  Grid Master: 2 ENIs, EIP on LAN1, #infoblox-config
    desktop/                  Windows Server 2022 + PowerShell bootstrap
      templates/desktop-init.ps1.tpl
    bypass-host/              Ubuntu host pinned to a public resolver
      templates/bypass-init.sh.tpl

scripts/
  nios_wapi.py                WAPI client: version probe, verbs, restart, readiness
  domains.py                  the blocked domain sets and RPZ object names
  bootstrap_nios.py           setup-time groundwork: DNS on, recursion, forwarders
  create_rpz_feed.py          builds the RPZ and all 42 block rules in one command
  configure_rpz.py            idempotent configuration CLI
  bypass_host.py              DNS lookups on the unmanaged host, over SSH
  lock_dns_egress.py          rewrites the bypass host's egress to close the gap
  verify_rpz.py               per-challenge verification, drives the check scripts
  desktop_dns.py              runs DNS lookups on the desktop over WinRM
  wait_for_nios.py            blocks until the Grid Master and desktop are up
  setup_dns.py                publishes the per-participant Route 53 names
  cleanup_dns_records.py      removes them again
  requirements.txt
```

## Deploy

Inside Instruqt this is automatic. By hand:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # then fill it in
terraform init
terraform apply

export GM_IP=$(terraform output -raw gm_public_ip)
export GM_LAN1_PRIVATE_IP=$(terraform output -raw gm_lan1_private_ip)
export DESKTOP_IP=$(terraform output -raw desktop_public_ip)
export NIOS_ADMIN_PASSWORD='...'
export TF_VAR_windows_admin_password='...'

cd ../scripts
python3 wait_for_nios.py          # six to ten minutes
python3 bootstrap_nios.py         # DNS on, recursion scoped, forwarders set
python3 create_rpz_feed.py        # the RPZ and every block rule
python3 lock_dns_egress.py --status
python3 verify_rpz.py --stage all # smoke-test it
```

## Teardown

```bash
cd scripts && python3 cleanup_dns_records.py
cd ../terraform && terraform destroy -auto-approve
```

Everything the lab creates is in Terraform state — VPC, subnet, IGW, route
table, three security groups, three ENIs, three EIPs, the key pair and all three
instances. There is no CSP tenant to deallocate. The bypass security group's
egress is rewritten at runtime by `lock_dns_egress.py`, which `terraform
destroy` handles regardless; `ignore_changes = [egress]` stops a later apply
reverting the participant's remediation. `track_scripts/cleanup-shell`
runs both steps and retries the destroy once.

Every resource carries these tags, so anything orphaned is easy to find:

```
Environment=Lab  Project=NIOS-RPZ-GenAI  ManagedBy=Terraform
Track=nios-rpz-genai-block  Participant=<instruqt participant id>
```

## Expected runtime

| Phase | Time |
|---|---|
| `terraform apply` | 2–3 min |
| vNIOS boot, licence, Grid Manager up | 6–10 min |
| Windows boot and bootstrap | 4–5 min |
| Unmanaged host boot | <1 min |
| **Setup total** (waits run in parallel) | **~12 min** |
| Grid Master bootstrap (DNS, recursion, forwarders) | <1 min |
| Participant, six challenges | ~45 min |
| `terraform destroy` | 3–4 min |

Setup runs while the participant reads challenge 1, so the lab fits inside an
hour. `timelimit` in `track.yml` is 5400s (90 min) for headroom.

## Security posture

Tighter than the sibling NIOS labs in this organisation, in two places, both
deliberate:

- **Port 53 is reachable from inside the VPC only.** The other labs open it to
  `0.0.0.0/0`, which makes the Grid Master an open recursive resolver on the
  public internet — a DNS amplification source. The challenge checks work around
  the narrower rule by running lookups *on the desktop* over WinRM, which is a
  more faithful test anyway.
- **Outbound TCP and UDP 853 are excluded** from the desktop's egress rules, so
  DNS-over-TLS and DNS-over-QUIC cannot be used to bypass the RPZ. Security
  groups are allow-only, so this is done by splitting the port range around 853.

The unmanaged host is the deliberate exception: it starts with unrestricted
egress, including port 53 to any public resolver, because being outside policy
is the whole point of it. Challenge 5 has the participant close that with
`lock_dns_egress.py --lock`.

Still open by design, and worth knowing about:

- Grid Manager (443), SSH (22), RDP (3389) and WinRM (5985) accept traffic from
  `0.0.0.0/0`, because Instruqt's virtual browser and Guacamole containers have
  no published egress range. Narrow `management_ingress_cidrs` if you run this
  outside Instruqt.
- WinRM uses HTTP basic auth. Acceptable on a throwaway instance that exists for
  under an hour; not a pattern to copy elsewhere.

## Troubleshooting

### The RPZ licence

A local RPZ needs a **DNS Firewall** entitlement, which NIOS licenses under the
name **RPZ**. Temporary licensing covers it, so the `temp_license` line carries
the token alongside the others:

```
nios IB-V825 enterprise dns dhcp cloud rpz
```

The other NIOS labs in this organisation stop at `cloud` because none of them
needed DNS Firewall — that is why the token is not visible elsewhere in the
estate, not a sign that it is unavailable.

**Symptom:** `configure_rpz.py zone` fails, or the Response Policy Zones menu is
absent in Grid Manager. Confirm the entitlement landed:

```bash
ssh admin@<gm-ip>          # password is nios_admin_password
show license
```

If RPZ is not listed, `nios_temp_license` is a plain string variable, so
adjusting it needs no code change — set it in `terraform.tfvars` or export
`TF_VAR_nios_temp_license`. Two models are in use across the other labs if you
also need to change that: **IB-V825** (tech-summit-security-niosx,
instruqt-aws-dc-lab-full) and **IB-V926** (app-migration-niosx); bump
`nios_instance_type` alongside it.

### The Grid Master never answers WAPI

`wait_for_nios.py` gives it fifteen minutes. If it times out:

```bash
aws ec2 get-console-output --region eu-central-1 --instance-id $(cd terraform && terraform output -raw gm_instance_id)
```

Most common causes: the AMI ID is for a different region; the instance type is
too small for the licensed model; the two ENIs landed in different AZs (they
cannot — the module uses one subnet, but check if you have edited it).

### The desktop resolves AI domains that should be blocked

In order of likelihood:

1. **Cached answer.** `ipconfig /flushdns` on the desktop, and restart Edge,
   which keeps its own cache.
2. **DNS not restarted** after the rule change. Grid Manager shows a
   *Restart Services* banner; it has to be clicked.
3. **The desktop is not using the Grid Master.** On the desktop run
   `Get-DnsClientServerAddress`; it should show `10.100.0.11` only. If not, the
   PowerShell bootstrap failed — check `C:\user_data.log`.
4. **DoH is back on.** Check
   `HKLM\SOFTWARE\Policies\Microsoft\Edge\DnsOverHttpsMode` is `off`. The RPZ
   also blocks the DoH bootstrap names as a backstop.

### Everything is blocked, including the control domain

Recursion is off or the ACL is wrong. `python3 configure_rpz.py status` shows
both. Re-check that `10.100.0.0/24` is an **Allow** entry under
`allow_recursion`.

### The desktop never answers WinRM

Windows takes four to five minutes and the bootstrap adds thirty seconds of
deliberate sleep. If it never comes up, fetch the password directly and RDP in
to read `C:\user_data.log`:

```bash
cd terraform
aws ec2 get-password-data --region eu-central-1 \
  --instance-id $(terraform output -raw desktop_instance_id) \
  --priv-launch-key $(terraform output -raw private_key_path)
```

### A challenge check fails with no explanation

Run the underlying verifier directly — it prints every assertion, not just the
failing one:

```bash
cd scripts
python3 verify_rpz.py --stage rpz
python3 configure_rpz.py status
```
