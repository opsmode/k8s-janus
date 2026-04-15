#!/usr/bin/env python3
"""Bump the image tag in the Janus ApplicationSet."""
import re
import sys

tag = sys.argv[1]
f = "gitops/apps/k8s-janus-central.yaml"
content = open(f).read()
updated = re.sub(r'tag: "[^"]*"', f'tag: "{tag}"', content)
open(f, "w").write(updated)
