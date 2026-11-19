"""Linux worker limits must preserve stricter parent limits."""

from __future__ import annotations

import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from services.knowledge.parse_worker import (configure_linux_limits,
                                             set_linux_cpu_budget)


class ParserLinuxLimitTests(unittest.TestCase):
    def test_inherited_limits_and_per_conversion_cpu_budget(self) -> None:
        memory = 5 * 1024 * 1024 * 1024
        limits = {1: (memory, -1), 2: (200, -1)}
        fake = SimpleNamespace(
            RLIMIT_AS=1, RLIMIT_CPU=2, RLIM_INFINITY=-1, RUSAGE_SELF=3,
            getrlimit=lambda kind: limits[kind],
            setrlimit=lambda kind, pair: limits.__setitem__(kind, pair),
            getrusage=lambda _: SimpleNamespace(ru_utime=12.4, ru_stime=3.2),
        )
        with patch.object(sys, "platform", "linux"), patch.dict(sys.modules, {"resource": fake}):
            configure_linux_limits()
            self.assertEqual(limits[1], (memory, memory))
            self.assertEqual(limits[2], (200, 200))
            set_linux_cpu_budget(60)
            self.assertEqual(limits[2], (76, 200))

    def test_exhausted_worker_fails_without_raising_hard_limit(self) -> None:
        limits = {2: (20, 20)}
        fake = SimpleNamespace(
            RLIMIT_CPU=2, RLIM_INFINITY=-1, RUSAGE_SELF=3,
            getrlimit=lambda kind: limits[kind],
            getrusage=lambda _: SimpleNamespace(ru_utime=18.1, ru_stime=1.5),
            setrlimit=lambda kind, pair: limits.__setitem__(kind, pair),
        )
        with patch.object(sys, "platform", "linux"), patch.dict(sys.modules, {"resource": fake}):
            with self.assertRaisesRegex(RuntimeError, "exhausted"):
                set_linux_cpu_budget(60)
        self.assertEqual(limits[2], (20, 20))


if __name__ == "__main__":
    unittest.main()
