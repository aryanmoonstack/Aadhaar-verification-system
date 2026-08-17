"""avs.api — the REST surface.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 7
Provides : create_app(), CallbackDispatcher, request/response models
Consumes : avs.pipeline, avs.worker, avs.storage, avs.truststore
Used by  : Spring AvsClient (Step 10)
Status   : COMPLETE

    POST /v1/verify          pre-signed URLs   -> 202
    POST /v1/verify/upload   multipart         -> 202
    POST /v1/verify/sync     multipart, blocks -> 200  (admin/debug)
    GET  /v1/verify/{job_id} poll
    GET  /health /ready /metrics

★ /ready fails when the trust store has no usable certificate. The service would
  otherwise answer every genuine document with ERROR while looking healthy.
"""

from avs.api.app import AppState, create_app
from avs.api.callbacks import CallbackDispatcher
from avs.api.models import JobAccepted, JobStatusResponse, ReadyResponse, VerifyUrlRequest

__all__ = [
    "AppState",
    "CallbackDispatcher",
    "JobAccepted",
    "JobStatusResponse",
    "ReadyResponse",
    "VerifyUrlRequest",
    "create_app",
]
