"""
tests/_helpers.py
─────────────────
Shared test plumbing.

`mock_transport(router)` wraps a respx MockRouter as a real httpx transport.
Any request a test did NOT explicitly mock returns 404 instead of raising —
so a module can freely probe many paths (e.g. /uploads/, /.git/config, error
pages) while a test only mocks the one or two that matter for the scenario.

Routes with an explicit `side_effect=httpx.ConnectError(...)` still raise, so
the "request error → no crash" tests continue to exercise the modules'
try/except httpx.RequestError paths.
"""

import httpx
from respx.models import AllMockedAssertionError


def mock_transport(router) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        try:
            return router.handler(request)
        except AllMockedAssertionError:
            # Path the test didn't mock — behave as if it simply doesn't exist.
            return httpx.Response(404, text="Not Found")

    return httpx.MockTransport(handler)
