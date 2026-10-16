#!/bin/sh
# Provisions real dependencies the tests exercise (runs inside the CI container).
set -eu
pip install -q --disable-pip-version-check --root-user-action=ignore cryptography
