"""avs.qr — QR decoder cascade.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 5
Provides : QrDecoderCascade.decode(variants) -> DecodeResult, PayloadKind,
           classify_payload(), decoder backends, decoder_availability()
Consumes : avs.contracts, OpenCV, zxing-cpp / pyzbar (optional)
Used by  : the Step 6 pipeline
Status   : COMPLETE

THE LOOP ORDER IS THE DESIGN
    for variant in variants:      # lazy, cheapest-first from Step 4
        for decoder in decoders:  # cheap relative to another variant

Stopping at the first success is what makes Step 4's tier ordering pay off.

Every decoder backend is optional. pyzbar needs a system libzbar; the WeChat
detector needs opencv-contrib model files. A host with only zxing-cpp and
OpenCV still works — same degradation rule as the AI layer.
"""

from avs.qr.cascade import (
    MIN_SECURE_QR_DIGITS,
    PayloadKind,
    QrDecoderCascade,
    classify_payload,
)
from avs.qr.decoders import (
    Decoder,
    OpenCvDecoder,
    WeChatDecoder,
    ZbarDecoder,
    ZxingDecoder,
    available_decoders,
    decoder_availability,
)

__all__ = [
    "MIN_SECURE_QR_DIGITS",
    "Decoder",
    "OpenCvDecoder",
    "PayloadKind",
    "QrDecoderCascade",
    "WeChatDecoder",
    "ZbarDecoder",
    "ZxingDecoder",
    "available_decoders",
    "classify_payload",
    "decoder_availability",
]
