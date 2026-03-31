from __future__ import annotations

from .price import PriceManipulationChecker
from .session import SessionReplayChecker
from .race import RaceConditionChecker
from .overclaim import OverclaimingChecker
from .verify import PaymentVerificationChecker
from .inject import Malicious402Checker
from .dos import DoSChecker

ALL_CHECKERS = [
    PriceManipulationChecker,
    SessionReplayChecker,
    RaceConditionChecker,
    OverclaimingChecker,
    PaymentVerificationChecker,
    Malicious402Checker,
    DoSChecker,
]

QUICK_CHECKERS = [
    PriceManipulationChecker,
    Malicious402Checker,
    SessionReplayChecker,
]
