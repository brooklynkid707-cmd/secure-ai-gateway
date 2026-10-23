"""Secure AI Gateway - a policy-enforcing reverse proxy for OpenAI-compatible LLM endpoints.

The package is organised as a request pipeline::

    client -> auth -> policy -> dlp -> injection -> upstream -> output_guard -> audit -> client

Every stage is importable and testable on its own; ``server.py`` wires them
together behind a Flask application that mirrors the upstream API shape.
"""

__version__ = "1.0.0"
