# Wazuh View

Local Wazuh agent status for the [Omarchy](https://omarchy.org/) Quickshell bar. SCA policy results, FIM baseline, rootcheck activity, effective configuration, and recent agent log lines, all inside the bar, no separate GUI window.

This plugin talks only to the local agent's own files and databases. It does not connect to a Wazuh manager or the Wazuh API, so it works even on an agent that has never reported to a manager, and it never sends anything anywhere.

## Features

- Connection status, last keepalive, and message count from the agent's own state file
- Module enablement matrix (FIM, rootcheck, SCA, active response) and live process status
- SCA policy scan results, pass/fail totals, and failed checks with remediation text
- FIM baseline: count of monitored paths and a sample of what is being watched
- Rootcheck: enabled state and recent scan activity parsed from the agent log
- Effective configuration: FIM directories, log sources, SCA policies, active response commands, manager address
- Recent agent log lines with error and warning counts
- Bar icon changes color when something needs attention

## What this plugin never touches

- `etc/client.keys`, the file holding the agent's shared authentication key, is never read
- No agent file or database is ever written to; every read goes through SQLite in read-only mode where a database is involved
- No network calls, no manager connection, no Wazuh API calls
- No command is ever run through a shell; the only subprocess invoked is the agent's own `bin/wazuh-control status`, using its resolved absolute path

## Requirements

- Omarchy with Quickshell
- Python 3
- A local Wazuh agent installation (checked at `/var/ossec` or `/opt/ossec` by default; see below to point elsewhere)

## Agent install path

The install path is never hardcoded to a single location. At each refresh the
helper checks, in order:

1. the `WAZUH_HOME` environment variable
2. the `OSSEC_HOME` environment variable
3. `/var/ossec`
4. `/opt/ossec`

The first candidate that has both a `bin/` directory and `etc/ossec.conf` is
used. If none match, the panel reports that no agent was detected instead of
guessing.

## Permissions

Several agent files (`logs/ossec.log`, the SCA and FIM databases, the state
file) are typically owned by `root:wazuh` and not world readable. If a
section shows "Permission denied", add your user to the `wazuh` group and
log back in:

```bash
sudo usermod -aG wazuh $USER
```

Everything degrades gracefully section by section: a permission issue in one
area (say, the SCA database) does not block the others from showing data.

## Installation

Add it with the Omarchy plugin CLI:

```bash
omarchy plugin add https://github.com/DevInBlack001/omarchy-wazuh-view --enable
```

Or manually: clone into your Omarchy plugins directory, then enable it.

```bash
git clone https://github.com/DevInBlack001/omarchy-wazuh-view ~/.config/omarchy/plugins/devinblack001.wazuh-view
omarchy plugin enable devinblack001.wazuh-view right
```

Then reload the shell:

```bash
omarchy restart shell
```

## Updating

```bash
omarchy plugin update devinblack001.wazuh-view
omarchy plugin update   # update every installed git-managed plugin
```

## Removing

```bash
omarchy plugin remove devinblack001.wazuh-view
```

Then reload the shell:

```bash
omarchy restart shell
```

## Usage

Click the shield icon in the bar to open the panel. Use the tab row (Overview,
SCA, FIM, Rootcheck, Config, Logs) to switch views. The panel refreshes every
5 seconds while open, and every 30 seconds in the background.

## Version differences

Wazuh's local database schemas for SCA and FIM can shift between versions.
Rather than assume one fixed schema, the helper inspects each database's
actual tables and columns at read time and adapts, so a version mismatch
degrades to less detail instead of a broken panel.

## Scope

This plugin is agent-side only. Full historical alerts, cross-agent
correlation, and vulnerability data live on the manager and are out of
scope here by design.

## License

MIT, see [LICENSE](LICENSE).
