#!/bin/bash
#
# Install Pebble Challenge Test Server for testing.
#
set -euo pipefail

arch=$(sh -c 'arch=$(uname -m); case "$arch" in aarch64) echo arm64 ;; x86_64) echo amd64 ;; armv7l|armv6l) echo arm ;; *) echo "$arch" ;; esac')

# Download and install
wget -nv "https://github.com/letsencrypt/pebble/releases/download/v${PEBBLECTS_VERSION}/pebble-challtestsrv-linux-${arch}.tar.gz" -O /tmp/pebble-challtestsrv.tar.gz
tar zxvf /tmp/pebble-challtestsrv.tar.gz -C /tmp

mv /tmp/pebble-challtestsrv-linux-${arch}/linux/${arch}/pebble-challtestsrv /usr/local/bin/pebble-challtestsrv
chown root:root /usr/local/bin/pebble-challtestsrv
chmod 0755 /usr/local/bin/pebble-challtestsrv

exit 0
