Decian Windows No-Admin Privilege Assessment Script
System Hardening & Security Baseline Checker

This script performs an automated security baseline assessment on Windows 10 and Windows 11 systems.
It is designed for non-admin environments, MSP deployments, and Decian’s internal risk-assessment workflow.

The script runs a series of checks and reports each one as PASS or FAIL, including a final summary count.

⚙️ What the Script Checks

Below is an overview of every check the script performs and what it looks for.

✔️ Check 1 — Supported Operating System

Verifies the OS version is still supported by Microsoft and receiving security updates.

✔️ Check 2 — Windows Update Currency

Checks when the last update was installed and ensures the system is not significantly out of date.

✔️ Check 3 — Disk Free Space

Fails if the system drive has critically low free space (default threshold: <10%).
Low free space impacts update installation, logging, and overall stability.

✔️ Check 4 — Antivirus / EDR Presence

Detects whether required security tools are installed, such as:

SentinelOne

Windows Defender

Other registered AV providers

✔️ Check 5 — Exposed or Risky Network Ports

Scans for open ports that commonly create remote-attack exposure.
Passes if no high-risk ports are exposed.

✔️ Check 6 — Firewall Profile Status

Checks all Windows Firewall profiles (Domain, Private, Public).
Fails if any profile is disabled.

✔️ Check 7 — “Allow All” Inbound Firewall Rules

Ensures there are no rules that allow inbound traffic from any source.
Passes if all inbound rules are scoped correctly.

✔️ Check 8 — Dangerous User Privileges

Identifies sensitive Windows privileges assigned to the current user.
Fails if privilege tokens like SeUndockPrivilege or similar high-risk privileges are present.

✔️ Check 9 — Stale or Insecure Local Accounts

Detects unused, stale, disabled, or insecure accounts.
Passes only if all accounts follow security policy.

✔️ Check 10 — Unauthorized Administrators

Enumerates the local Administrators group.
Fails if unexpected, unknown, or orphaned SIDs are present.

✔️ Check 11 — Insecure or Outdated Software

Looks for installed programs known to be outdated, end-of-life, or high-risk.

✔️ Check 12 — Required Logging Configuration

Confirms that important Windows audit logs are enabled, including:

Account logon

Object access

PowerShell logging

System events

✔️ Check 13 — Automatic Updates Setting

Verifies automatic updates are enabled.
Fails if the system is configured to not automatically update.

✔️ Check 14 — PowerShell Execution/Config

Validates PowerShell security settings, such as:

Execution policy

Module logging

Script block logging
Passes if PowerShell is configured securely.

📊 Example Output Summary
TOTAL PASSED: 7
TOTAL FAILED: 7


Each check prints a friendly message describing the PASS/FAIL status and what was detected.
