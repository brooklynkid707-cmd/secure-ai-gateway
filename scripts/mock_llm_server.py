#!/usr/bin/env python3
"""Run the bundled mock OpenAI-compatible upstream as a standalone process.

    python scripts/mock_llm_server.py --port 8081

Then point the gateway at it:

    python -m gateway run --policy config/balanced.yaml --upstream http://127.0.0.1:8081/v1/chat/completions

The mock is deterministic and keyword-driven (see ``gateway/mock_llm.py``). It
deliberately misbehaves on request - leaking its system prompt, inventing a
fake cloud key, emitting script tags, calling forbidden tools - so the
gateway's output controls have something to catch.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gateway.mock_llm import MockServer  # noqa: E402


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--verbose", action="store_true", help="log each request")
    args = parser.parse_args()
    server = MockServer(args.host, args.port, verbose=args.verbose)
    print(f"mock LLM upstream listening on {server.url}")
    try:
        server.httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
