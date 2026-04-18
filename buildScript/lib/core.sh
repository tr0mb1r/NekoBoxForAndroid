#!/bin/bash
set -e

buildScript/lib/core/init.sh
buildScript/lib/core/build.sh

# Hardening fork: also pull the sing-box geoip / geosite assets so the
# routing rules ("geosite:cn", "geoip:cn", etc.) actually have a database
# to look up against. Without this, sing-box prints
# "code <foo> not exists" at VPN-start time and routes that reference
# the .db files fail to materialize. Upstream NekoBox CI runs this via
# a separate "./run init action gradle" step (see .github/workflows/*),
# but local builds need it inline.
buildScript/lib/assets.sh