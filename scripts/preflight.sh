#!/bin/bash
#
# Run this before pushing. It catches the class of bug that otherwise only
# surfaces at `terraform apply` — which, in a track, means several minutes into
# a lab start with the participant already waiting.
#
#   ./scripts/preflight.sh
#
# Two real failures got through to a live lab start before this existed:
#
#   * an em dash in a security-group description, which AWS rejects
#     ("doesn't comply with restrictions ^[0-9A-Za-z_ .:/()#,@\[\]+=&;{}!$*-]*$")
#   * a single-dollar brace expression inside a comment in a .tpl file, which
#     templatefile() tried to evaluate as an expression
#
# `terraform validate` catches both. `terraform fmt` catches neither — it only
# checks HCL layout and evaluates nothing. Running fmt alone was the mistake.
#
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FAILED=0
step() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  OK    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; FAILED=1; }

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
# validation, which is where both of the escaped bugs lived.
step "terraform validate"
if OUT=$(terraform -chdir=terraform validate 2>&1); then
  ok "configuration is valid"
else
  bad "configuration is invalid"
  echo "$OUT" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^/    /'
fi

# --- 4. Rendered user_data ---------------------------------------------------
# validate proves the templates parse; this proves what they produce is a
# script the target OS can actually run.
step "rendered user_data"

render() {
  echo "jsonencode($1)" | terraform -chdir=terraform console 2>/dev/null \
    | python3 -c "import json,sys; raw=sys.stdin.read().strip(); print(json.loads(json.loads(raw)) if raw.startswith('\"') else raw, end='')"
}

BYPASS_TPL='templatefile("${path.module}/modules/bypass-host/templates/bypass-init.sh.tpl", {public_resolver="8.8.8.8", fallback_resolver="1.1.1.1", gm_ip="10.100.0.11"})'
BYPASS_TPL=${BYPASS_TPL//\$\{path.module\}/.}

if render "$BYPASS_TPL" > /tmp/preflight-bypass.sh 2>/dev/null && [ -s /tmp/preflight-bypass.sh ]; then
  if bash -n /tmp/preflight-bypass.sh 2>/dev/null; then
    ok "bypass-init.sh.tpl renders to valid bash"
  else
    bad "bypass-init.sh.tpl renders to invalid bash"
    bash -n /tmp/preflight-bypass.sh 2>&1 | sed 's/^/    /'
  fi

  # Every helper script the user_data writes onto the host, checked separately:
  # a broken heredoc body would not show up in the outer script's syntax.
  python3 - <<'PY'
import os, re, subprocess, sys, tempfile
src = open("/tmp/preflight-bypass.sh").read()
found = 0
for m in re.finditer(r"cat > (/home/ubuntu/[a-z-]+\.sh) <<'?(\w+)'?\n(.*?)\n\2\n", src, re.S):
    path, _, body = m.groups(); found += 1
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(body); tmp = f.name
    r = subprocess.run(["bash", "-n", tmp], capture_output=True, text=True)
    tag = "OK   " if r.returncode == 0 else "FAIL "
    print(f"  {tag} helper {os.path.basename(path)}")
    if r.returncode: print("    " + r.stderr.strip())
    os.unlink(tmp)
if found == 0:
    print("  FAIL  no helper scripts found in the rendered user_data")
    sys.exit(1)
PY
  [ $? -ne 0 ] && FAILED=1

  # Look for the variable *names*, not for brace syntax. In rendered output an
  # escaped expression such as ${status:-TIMEOUT} — which bash is meant to
  # expand — is shape-identical to an unsubstituted variable, so only the names
  # distinguish a real failure.
  leftover=$(grep -nE '\$\{(public_resolver|fallback_resolver|gm_ip)\}' \
               /tmp/preflight-bypass.sh || true)
  if [ -z "$leftover" ]; then
    ok "every template variable was substituted"
  else
    bad "template variables left unsubstituted:"
    echo "$leftover" | sed 's/^/    /'
  fi

  # And the values really did land.
  missing=""
  for v in 8.8.8.8 1.1.1.1 10.100.0.11; do
    grep -q "$v" /tmp/preflight-bypass.sh || missing="$missing $v"
  done
  if [ -z "$missing" ]; then
    ok "substituted values present in the output"
  else
    bad "expected values missing from the output:$missing"
  fi
else
  bad "could not render bypass-init.sh.tpl"
fi

DESKTOP_TPL='templatefile("./modules/desktop/templates/desktop-init.ps1.tpl", {admin_password="x", dns_server_ip="10.100.0.11", grid_manager_url="https://example"})'
if render "$DESKTOP_TPL" > /tmp/preflight-desktop.ps1 2>/dev/null && [ -s /tmp/preflight-desktop.ps1 ]; then
  if head -1 /tmp/preflight-desktop.ps1 | grep -q '<powershell>' \
     && grep -q '</powershell>' /tmp/preflight-desktop.ps1; then
    ok "desktop-init.ps1.tpl renders with its EC2 wrapper intact"
  else
    bad "desktop-init.ps1.tpl is missing the <powershell> wrapper"
  fi
else
  bad "could not render desktop-init.ps1.tpl"
fi

# --- 5. Python ---------------------------------------------------------------
step "python"
if python3 -m py_compile scripts/*.py 2>/dev/null; then
  ok "all scripts compile"
  rm -rf scripts/__pycache__
else
  bad "a script failed to compile"
  python3 -m py_compile scripts/*.py 2>&1 | sed 's/^/    /'
fi

# --- Verdict -----------------------------------------------------------------
printf '\n'
if [ "$FAILED" -eq 0 ]; then
  echo "PREFLIGHT PASSED — safe to push."
else
  echo "PREFLIGHT FAILED — fix the above before pushing."
fi
exit "$FAILED"
