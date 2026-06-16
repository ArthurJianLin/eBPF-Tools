#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Thin wrapper — stack sampling is built into verify_symbol.sh (-s flag).
exec "$(dirname "$0")/verify_symbol.sh" -s "$@"
