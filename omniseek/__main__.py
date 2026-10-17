# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The OmniSeek Authors
"""`python -m omniseek` runs the CLI."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
