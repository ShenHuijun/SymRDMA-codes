#!/bin/bash
# Control-plane benchmark wrapper.
exec python3 "$(dirname "$0")/symtest/__main__.py" ctl "$@"
