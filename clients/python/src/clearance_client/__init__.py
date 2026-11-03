"""clearance-core-client: the Python client of the Clearance core's HTTP API (contract/clearance-core.json).

    from clearance_client import CoreClient, CoreUnavailable, EvaluationRequest

    core = CoreClient("http://clearance-core.clearance-system:8080",
                      token_file="/var/run/secrets/tokens/clearance", provider="example-gateway")
    try:
        res = core.evaluate(request)
    except CoreUnavailable:
        ...  # the outage policy: fail closed, fast
    if not res.decision:
        ...  # a deny: res.context.rule, message, hint

The models are generated from the contract (tools/pyclient); the transport is the standard library only.
"""

from ._codec import DecodeError, Model
from ._models import *  # noqa: F401,F403  (the generated request and answer types)
from ._models import CONTRACT_VERSION, MODELS, OPERATIONS, RECORD_KINDS
from ._version import __version__
from .client import (
    CLOSED,
    DEFAULT_BREAKER_COOLDOWN,
    DEFAULT_BREAKER_THRESHOLD,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    HALF_OPEN,
    OPEN,
    AsyncCoreClient,
    CoreClient,
)
from .errors import (
    BREAKER_OPEN,
    CONNECTION,
    SERVER_ERROR,
    TIMEOUT,
    BadResponse,
    ClearanceClientError,
    CoreRequestError,
    CoreUnavailable,
    TokenUnavailable,
)

__all__ = [
    "AsyncCoreClient", "BREAKER_OPEN", "BadResponse", "CLOSED", "CONNECTION", "CONTRACT_VERSION",
    "ClearanceClientError", "CoreClient", "CoreRequestError", "CoreUnavailable", "DEFAULT_BREAKER_COOLDOWN",
    "DEFAULT_BREAKER_THRESHOLD", "DEFAULT_RETRIES", "DEFAULT_TIMEOUT", "DecodeError", "HALF_OPEN", "MODELS", "Model",
    "OPEN", "OPERATIONS", "RECORD_KINDS", "SERVER_ERROR", "TIMEOUT", "TokenUnavailable", "__version__",
    *MODELS,
]
