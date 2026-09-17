"""DTT-ECDSA on SUMO —— 动态可追踪门限 ECDSA 的车联网仿真实现。"""

from .entities import (TA, RSU, TMC, Tracer, Vehicle, SignatureShare,
                       AggregateSignature, SessionCiphertext, TraceResult,
                       verify_signature, random_plate)
from .vanet import (VANETReportSession, LinkContext, StaticLinkContext,
                    PhaseTiming, RegisteredVehicle, RSU_RANGE_M,
                    threshold_from_severity, classify_severity,
                    SEVERITY_THRESHOLD)
from .v2i import V2XChannel, model_summary, max_range_m
from . import curve, crypto, message, search, v2i, vanet, console

__all__ = [
    "TA", "RSU", "TMC", "Tracer", "Vehicle", "SignatureShare",
    "AggregateSignature", "SessionCiphertext", "TraceResult",
    "verify_signature", "random_plate",
    "VANETReportSession", "LinkContext", "StaticLinkContext", "PhaseTiming",
    "RegisteredVehicle", "RSU_RANGE_M", "threshold_from_severity",
    "classify_severity", "SEVERITY_THRESHOLD",
    "V2XChannel", "model_summary", "max_range_m",
    "curve", "crypto", "message", "search", "v2i", "vanet", "console",
]

__version__ = "1.0"
