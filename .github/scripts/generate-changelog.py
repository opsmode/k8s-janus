#!/usr/bin/env python3
"""
Generate a fancy GitHub Release body from conventional commits.

Usage:
    python3 generate-changelog.py <prev_tag> <new_tag> <image> <output_file>
"""
import re
import subprocess
import sys

PREV_TAG, NEW_TAG, IMAGE, OUT = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

# Commit range
if PREV_TAG:
    log = subprocess.check_output(
        ["git", "log", f"{PREV_TAG}..{NEW_TAG}", "--pretty=format:%s|||%H"],
        text=True,
    ).splitlines()
else:
    log = subprocess.check_output(
        ["git", "log", "--pretty=format:%s|||%H"],
        text=True,
    ).splitlines()

# Buckets: (display order, emoji, heading, regex)
BUCKETS = [
    ("breaking", "💥", "Breaking Changes",  r"^(feat|fix|refactor)(\([^)]+\))?!:"),
    ("feat",     "✨", "New Features",       r"^feat(\([^)]+\))?:"),
    ("fix",      "🐛", "Bug Fixes",          r"^fix(\([^)]+\))?:"),
    ("security", "🔒", "Security",           r"^(security|sec)(\([^)]+\))?:"),
    ("perf",     "⚡", "Performance",        r"^perf(\([^)]+\))?:"),
    ("refactor", "♻️", "Improvements",       r"^refactor(\([^)]+\))?:"),
    ("deps",     "📦", "Dependencies",       r"^chore\(deps\)|^(chore|build).*bump"),
    ("chore",    "🔧", "CI / Chores",        r"^(chore|ci|build|test)(\([^)]+\))?:"),
]

# Compile patterns
compiled = [(k, em, h, re.compile(p, re.IGNORECASE)) for k, em, h, p in BUCKETS]

groups: dict[str, list[str]] = {k: [] for k, *_ in BUCKETS}
skip_re = re.compile(r"^ci: bump chart to|^Merge ")

for line in log:
    if "|||" not in line:
        continue
    msg, sha = line.split("|||", 1)
    msg = msg.strip()
    if not msg or skip_re.match(msg):
        continue

    matched = False
    for k, _em, _h, pat in compiled:
        if pat.match(msg):
            # Strip conventional prefix, keep scope if useful
            clean = re.sub(r"^[a-z]+(\([^)]+\))?!?: ?", "", msg).strip()
            clean = clean[0].upper() + clean[1:] if clean else clean
            groups[k].append(f"- {clean}")
            matched = True
            break
    if not matched:
        clean = msg[0].upper() + msg[1:] if msg else msg
        groups["chore"].append(f"- {clean}")

# Build body
lines = []
lines.append(f"## What's changed in {NEW_TAG}\n")

any_entries = False
for k, em, heading, _pat in BUCKETS:
    entries = groups[k]
    if not entries:
        continue
    any_entries = True
    lines.append(f"### {em} {heading}")
    lines.extend(entries)
    lines.append("")

if not any_entries:
    lines.append("_No notable changes._\n")

# Footer
lines.append("---")
lines.append("")
lines.append("## 🐳 Docker Image")
lines.append("")
lines.append("```")
lines.append(f"{IMAGE}:{NEW_TAG}")
lines.append("```")
lines.append("")
lines.append("## ⎈ Install / Upgrade via Helm")
lines.append("")
lines.append("```bash")
lines.append("helm repo add k8s-janus https://infroware.github.io/k8s-janus")
lines.append("helm repo update")
lines.append("helm upgrade --install k8s-janus k8s-janus/k8s-janus \\")
lines.append("  --namespace k8s-janus --create-namespace")
lines.append("```")

if PREV_TAG:
    lines.append("")
    lines.append(f"**Full diff:** [`{PREV_TAG} → {NEW_TAG}`]"
                 f"(https://github.com/infroware/k8s-janus/compare/{PREV_TAG}...{NEW_TAG})")

with open(OUT, "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Changelog written to {OUT} ({len(log)} commits processed)")
