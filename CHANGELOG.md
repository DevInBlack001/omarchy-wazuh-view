# Changelog

All notable changes to this plugin are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-08-29

### Added

- Bar-widget panel with six tabs: Overview, SCA, FIM, Rootcheck, Config, Logs
- Overview tab: connection status, last keepalive, message count, manager address, agent version, install path, module enablement matrix, live process status
- SCA tab: pass/fail totals and failed checks with remediation text, read from the local SCA database
- FIM tab: count of monitored paths and a sample of what is being watched, read from the local FIM database
- Rootcheck tab: enabled state and recent activity parsed from the agent log
- Config tab: FIM directories, log sources, SCA policies, active response commands, manager address
- Logs tab: recent agent log lines with error and warning counts
- Agent install path detection via `WAZUH_HOME`/`OSSEC_HOME` env vars with a fallback search, never a single hardcoded path
- SCA/FIM database access adapts to the actual table and column names present, since the schema can shift between Wazuh versions
