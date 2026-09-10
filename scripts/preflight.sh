#!/bin/bash
#
# Run this before pushing. It catches the class of bug that otherwise only
# surfaces at `terraform apply` — which, in a track, means several minutes into
# a lab start with the participant already waiting.
#
#   ./scripts/preflight.sh
#
# Three real failures got through to a live lab start before this existed:
#
#   * an em dash in a security-group description, which AWS rejects
#     ("doesn't comply with restrictions ^[0-9A-Za-z_ .:/()#,@\[\]+=&;{}!$*-]*$")
#   * a single-dollar brace expression inside a comment in a .tpl file, which
#     templatefile() tried to evaluate as an expression
#   * a fix that was made locally, never committed, and therefore never reached
#     the GitHub repo the track clones at run time
#
# `terraform validate` catches the first two. `terraform fmt` catches neither —
# it only checks HCL layout and evaluates nothing. Running fmt alone was the
# original mistake. The last one is caught by the git check at the end.
#
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FAILED=0
step() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  OK    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; FAILED=1; }
warn() { printf '  WARN  %s\n' "$1"; }

# --- 1. HCL formatting -------------------------------------------------------
step "terraform fmt"
if terraform -chdir=terraform fmt -check -recursive >/dev/null 2>&1; then
  ok "formatting is canonical"
else
  bad "run: terraform -chdir=terraform fmt -recursive"
fi

# --- 2. Providers ------------------------------------------------------------
step "terraform init"
if terraform -chdir=terraform init -backend=false -input=false >/dev/null 2>&1; then
  ok "providers resolved"
else
  bad "terraform init failed"
  echo "  cannot validate without providers, stopping"
  exit 1
fi

# --- 3. The check that matters ----------------------------------------------
# Evaluates every templatefile() call and every provider-side attribute
# validation, which is where both of the escaped Terraform bugs lived.
step "terraform validate"
if OUT=$(terraform -chdir=terraform validate 2>&1); then
  ok "configuration is valid"
else
  bad "configuration is invalid"
  echo "$OUT" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^/    /'
fi

# --- 4. Rendered user_data ---------------------------------------------------
# validate proves the template parses; this proves what it produces is
# something the target OS can actually run.
step "rendered user_data"

render() {
  echo "jsonencode($1)" | terraform -chdir=terraform console 2>/dev/null \
    | python3 -c "import json,sys; raw=sys.stdin.read().strip(); print(json.loads(json.loads(raw)) if raw.startswith('\"') else raw, end='')"
}

DESKTOP_TPL='templatefile("./modules/desktop/templates/desktop-init.ps1.tpl", {admin_password="Sup3rSecret!", dns_server_ip="10.100.0.200", portal_url="https://portal.infoblox.com"})'

if render "$DESKTOP_TPL" > /tmp/preflight-desktop.ps1 2>/dev/null \
   && [ -s /tmp/preflight-desktop.ps1 ]; then

  if head -1 /tmp/preflight-desktop.ps1 | grep -q '<powershell>' \
     && grep -q '</powershell>' /tmp/preflight-desktop.ps1; then
    ok "desktop-init.ps1.tpl renders with its EC2 wrapper intact"
  else
    bad "desktop-init.ps1.tpl is missing the <powershell> wrapper"
  fi

  # Look for the variable *names*, not for brace syntax. In rendered output an
  # escaped expression such as $${env:TEMP} — which PowerShell is meant to
  # expand — is shape-identical to an unsubstituted variable, so only the
  # names distinguish a real failure.
  leftover=$(grep -nE '\$\{(admin_password|dns_server_ip|portal_url)\}' \
               /tmp/preflight-desktop.ps1 || true)
  if [ -z "$leftover" ]; then
    ok "every template variable was substituted"
  else
    bad "template variables left unsubstituted:"
    echo "$leftover" | sed 's/^/    /'
  fi

  # And the values really did land.
  missing=""
  for v in "10.100.0.200" "portal.infoblox.com"; do
    grep -q "$v" /tmp/preflight-desktop.ps1 || missing="$missing $v"
  done
  if [ -z "$missing" ]; then
    ok "substituted values present in the output"
  else
    bad "expected values missing from the output:$missing"
  fi

  # The DFP is useless if the desktop resolves over DoH instead, so the
  # registry writes that disable it are load-bearing, not hardening.
  if grep -q "DnsOverHttpsMode" /tmp/preflight-desktop.ps1 \
     && grep -q "EnableAutoDoh" /tmp/preflight-desktop.ps1; then
    ok "DNS-over-HTTPS is disabled in the rendered script"
  else
    bad "the rendered desktop script no longer disables DNS-over-HTTPS, so "\
"queries can bypass the DFP and Application Discovery will stay empty"
  fi
else
  bad "could not render desktop-init.ps1.tpl"
fi

# --- 5. NIOS-X join token wiring --------------------------------------------
# The host silently never registers if the cloud-config key is wrong, and the
# only symptom is a lab that times out waiting for it, so check the shape.
step "niosx cloud-config"
NIOSX_MAIN="terraform/modules/niosx-dfp/main.tf"
if [ -f "$NIOSX_MAIN" ]; then
  if grep -q "#cloud-config" "$NIOSX_MAIN" \
     && grep -q "host_setup:" "$NIOSX_MAIN" \
     && grep -q "jointoken:" "$NIOSX_MAIN"; then
    ok "user_data carries #cloud-config host_setup/jointoken"
  else
    bad "$NIOSX_MAIN is missing the #cloud-config host_setup: jointoken: keys"
  fi
else
  bad "$NIOSX_MAIN not found"
fi

# --- 6. Python ---------------------------------------------------------------
step "python"
if python3 -m py_compile scripts/*.py 2>/dev/null; then
  ok "all scripts compile"
  rm -rf scripts/__pycache__
else
  bad "a script failed to compile"
  python3 -m py_compile scripts/*.py 2>&1 | sed 's/^/    /'
fi

# Every script imports from csp_api; a rename there breaks everything at once
# and only at run time.
step "imports"
if (cd scripts && python3 -c "
import importlib, sys
mods = ['csp_api','domains','desktop_dns','app_discovery','security_policy',
        'setup_dfp','provision_tenant','generate_ai_traffic','verify_lab',
        'discover_td_api']
bad = []
for m in mods:
    try:
        importlib.import_module(m)
    except Exception as e:
        bad.append(f'{m}: {e}')
if bad:
    print('\n'.join(bad)); sys.exit(1)
" 2>&1); then
  ok "every module imports cleanly"
else
  bad "a module failed to import (see above)"
fi

# --- 6b. regression tests ----------------------------------------------------
# Offline, no credentials, no tenant. Every assertion here exists because the
# thing it checks broke a live lab start:
#
#   test_csp_api      switch_account() accepted only HTTP 200 against an
#                     endpoint that answers 201, and the API key expiry was a
#                     hardcoded date against a rolling ~13 month cap
#   test_setup_dfp    host readiness required one of four undocumented status
#                     strings, so a host that had registered fine stalled for
#                     the full fifteen minutes
#   test_desktop_dns  a ten-domain run against a DFP that was not serving
#                     outlived the WinRM timeout, because each lookup waited
#                     out its own retry schedule. Looked like a hang.
#   test_domains      approving only ChatGPT would enforce a policy that
#                     breaks ChatGPT, because it depends on openai.com for
#                     auth and API traffic. expected_split() moved from one
#                     approved name to a list, and every caller had to move
#                     with it or silently read only the first one.
#
# The common thread is asserting a specific value, or an unbounded wait,
# against a system whose real behaviour was never confirmed. These tests pin
# down what was learned. The desktop suite also checks the PowerShell renders
# and balances, because it cannot be executed on the machine that writes it.
step "regression tests"
for suite in test_csp_api test_setup_dfp test_desktop_dns test_domains; do
  if TEST_OUT=$( (cd scripts && python3 "${suite}.py") 2>&1 ); then
    ok "${suite}: $(echo "$TEST_OUT" | grep -c '^  ok') assertions passed"
  else
    bad "${suite} failed"
    echo "$TEST_OUT" | grep -E "^  FAIL|^  -" | sed 's/^/    /'
  fi
done

# --- 7. Uncommitted work -----------------------------------------------------
# The track clones this repo from GitHub at run time. A fix that is only on
# disk does not exist as far as the lab is concerned. This has bitten before.
step "git"
if git rev-parse --git-dir >/dev/null 2>&1; then
  if [ -z "$(git status --porcelain)" ]; then
    ok "working tree is clean"
  else
    warn "uncommitted changes - the track clones from GitHub, so these will NOT apply:"
    git status --porcelain | sed 's/^/    /'
  fi

  UPSTREAM=$(git rev-parse --abbrev-ref '@{upstream}' 2>/dev/null || echo "")
  if [ -n "$UPSTREAM" ]; then
    AHEAD=$(git rev-list --count "$UPSTREAM"..HEAD 2>/dev/null || echo 0)
    if [ "$AHEAD" = "0" ]; then
      ok "pushed to $UPSTREAM"
    else
      warn "$AHEAD commit(s) not pushed to $UPSTREAM - run: git push"
    fi
  fi
else
  warn "not a git repository, skipping"
fi

# --- Verdict -----------------------------------------------------------------
printf '\n'
if [ "$FAILED" -eq 0 ]; then
  echo "PREFLIGHT PASSED - safe to push."
else
  echo "PREFLIGHT FAILED - fix the above before pushing."
fi
exit "$FAILED"
