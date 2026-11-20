# Manual firewall-adapter test (written but unverified)

Status: **UNVERIFIED for real firewall enforcement**.

No real `netsh` or `iptables` command was executed while implementing or testing
Phase 6. The automated suite uses mocked `subprocess.run` and dry-run adapters
only. Real enforcement is UNVERIFIED until you run this checklist on a disposable
test host and record the results.

## Safety model

Real enforcement requires **all** of the following:

1. `PREVENTION_MODE=active`
2. `PREVENTION_ALLOW_REAL_ENFORCEMENT=true`
3. `CAPTURE_MODE` is not `simulation` (and `SENSOR_SIMULATION_MODE=false` when
   `CAPTURE_MODE` is unset)
4. `PREVENTION_KILL_SWITCH=false`
5. the target IP is valid and is not whitelisted, protected, a default gateway,
   the admin IP, or a DNS server

If any check fails, the engine uses a dry-run adapter. Simulation-tagged events
are always forced to dry-run, even with live/active settings.

Every firewall adapter builds an argument list and invokes it with
`subprocess.run(argv, shell=False)`. No shell strings are constructed.

---

## 1. Confirm the default is dry-run

From the repository root:

```powershell
.\.venv\Scripts\python.exe -c "from prevention.ip_blocker import real_enforcement_enabled; print('real_enforcement_enabled:', real_enforcement_enabled())"
```

Expected output:

```text
real_enforcement_enabled: False
```

If it prints `True`, stop and unset `PREVENTION_ALLOW_REAL_ENFORCEMENT`.

---

## 2. Preview the exact argv without executing it

This command builds the rule name and command lists only. It does **not** call
`block()`, `unblock()`, `subprocess.run`, `netsh`, or `iptables`.

```powershell
.\.venv\Scripts\python.exe -c "from prevention.ip_blocker import DryRunAdapter, _platform_adapter; ip='203.0.113.10'; a=DryRunAdapter(_platform_adapter()); rule=a.rule_name(ip); print('rule:', rule); print('block argv:', a.build_block_command(ip, rule)); print('unblock argv:', a.build_unblock_command(ip, rule)); print('list argv:', a.build_list_command()); print('block preview:', a.block(ip, 15).preview)"
```

Record the printed `rule`, `block argv`, `unblock argv`, and `list argv`.

Expected properties:

- `rule` starts with `AI-IDS-`.
- `block argv` is a Python list of strings, not a shell string.
- The documented test address `203.0.113.10` appears in the block argv.
- The unblock argv identifies the stable `AI-IDS-...` rule name.
- No `;`, `|`, `&&`, or backtick shell chaining appears in any argument.

On Windows the real adapter uses `netsh advfirewall firewall add rule ...`.
On Linux it uses `iptables` or `ip6tables` with `-I INPUT ... -j DROP ...`.

---

## 3. Dry-run end-to-end check (safe on this workstation)

Keep the default safe settings:

```powershell
Remove-Item Env:PREVENTION_MODE -ErrorAction SilentlyContinue
Remove-Item Env:PREVENTION_ALLOW_REAL_ENFORCEMENT -ErrorAction SilentlyContinue
```

Start the prevention worker if the stream services are already available:

```powershell
.\.venv\Scripts\python.exe run.py prevention-engine
```

Trigger a block through the API as an authenticated admin, or replay a
simulation candidate. For the API route, send JSON to:

```text
POST /api/v1/prevention/blocked-ips
```

Example body:

```json
{
  "ip_address": "203.0.113.10",
  "reason": "manual firewall dry-run check",
  "duration_minutes": 15
}
```

Authenticated JSON requests require the `X-CSRFToken` header from the signed-in
`/dashboard` meta tag.

Expected observations:

- The response reports a dry-run block.
- `blocked_ips.is_dry_run` is `true`.
- `blocked_ips.firewall_rule_name` starts with `AI-IDS-`.
- `prevention_actions.dry_run` is `true`.
- `prevention_actions.result` is `SIMULATED`.
- `prevention_actions.command_preview` matches the argv from step 2.
- No firewall rule is visible in the OS firewall.

---

## 4. Real-enforcement preview only (still no execution)

On the disposable test host, confirm the gate before enabling anything:

```powershell
$env:PREVENTION_MODE="active"
$env:PREVENTION_ALLOW_REAL_ENFORCEMENT="true"
Remove-Item Env:CAPTURE_MODE -ErrorAction SilentlyContinue
.\.venv\Scripts\python.exe -c "from prevention.ip_blocker import real_enforcement_enabled; print('real_enforcement_enabled:', real_enforcement_enabled())"
```

Expected output:

```text
real_enforcement_enabled: True
```

Now repeat step 2 to capture the exact argv that would be executed. Do not call
`block()` or `unblock()` on a real adapter during this preview.

If `CAPTURE_MODE=simulation` or `SENSOR_SIMULATION_MODE=true`, the expected
output remains `False`. Do not proceed unless you intentionally unset simulation
mode on the test host.

---

## 5. Real enforcement (only on a disposable test host)

Prerequisites:

- You are an administrator on the test host.
- The host is not a workstation or production sensor.
- `203.0.113.10` is a documentation-only address and is not in use.
- The admin IP, gateway IPs, DNS servers, whitelist, and protected CIDRs have been
  reviewed.
- You can remove the rule if the test fails.

Enable enforcement for the worker process:

```powershell
$env:PREVENTION_MODE="active"
$env:PREVENTION_ALLOW_REAL_ENFORCEMENT="true"
Remove-Item Env:CAPTURE_MODE -ErrorAction SilentlyContinue
$env:PREVENTION_KILL_SWITCH="false"
```

Start the worker:

```powershell
.\.venv\Scripts\python.exe run.py prevention-engine
```

Trigger one manual block through `POST /api/v1/prevention/blocked-ips` with the
same JSON body used in step 3. Record the returned block ID and rule name.

Verify the OS rule (read-only):

```powershell
Get-NetFirewallRule -DisplayName "AI-IDS-*"
```

On Linux:

```bash
sudo iptables -S INPUT | grep AI-IDS-
```

Expected observations:

- Exactly one managed rule exists for the documented test address.
- `blocked_ips.is_dry_run` is `false`.
- `prevention_actions.dry_run` is `false`.
- `prevention_actions.result` is `APPLIED`.
- `prevention_actions.command_preview` matches the step 4 argv.
- The active model remains `cicids-80k-no-port` and no registry files changed.

---

## 6. Remove the test rule

Preferred removal is the API route, using the block ID from step 5:

```text
POST /api/v1/prevention/blocked-ips/<block_id>/unblock
```

Example body:

```json
{
  "reason": "manual firewall verification cleanup"
}
```

Authenticated JSON requests require the `X-CSRFToken` header.

Expected observations:

- The block status becomes `RELEASED`.
- `prevention_actions.result` is `APPLIED` with `dry_run=false`.
- The `AI-IDS-...` rule no longer appears in the OS firewall.

Break-glass OS removal, only if the API path is unavailable, uses the exact rule
name recorded in step 5:

```powershell
netsh advfirewall firewall delete rule name="AI-IDS-<digest>"
```

On Linux, use the exact unblock argv from step 2 with `shell=False` semantics;
do not paste values from untrusted input into a shell string.

After cleanup, unset the real-enforcement variables:

```powershell
Remove-Item Env:PREVENTION_ALLOW_REAL_ENFORCEMENT -ErrorAction SilentlyContinue
Remove-Item Env:PREVENTION_MODE -ErrorAction SilentlyContinue
```

---

## Verification record

Until you complete steps 4-6 and report the following, real firewall enforcement
remains **UNVERIFIED**:

- host OS and whether it was disposable
- exact `rule`, `block argv`, and `unblock argv` from step 2
- `real_enforcement_enabled()` output from step 4
- block ID, rule name, and `prevention_actions.result`
- read-only OS firewall output
- cleanup confirmation that the rule was removed
