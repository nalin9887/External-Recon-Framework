import tempfile
import unittest
from pathlib import Path

from reconfw.nmap_phase import build_nmap_command
from reconfw.vuln_phase import _safe_nuclei_base


class SafetyInvariantTests(unittest.TestCase):
    def test_nmap_guardrails(self):
        cmd = build_nmap_command(
            "nmap",
            "192.0.2.10",
            Path("/tmp/out"),
            "full",
            "T3",
            2,
            "15m",
        )
        self.assertIn("-T3", cmd)
        self.assertNotIn("-T5", cmd)
        self.assertIn("--max-retries", cmd)
        self.assertEqual(cmd[cmd.index("--max-retries") + 1], "2")
        self.assertEqual(cmd[cmd.index("--host-timeout") + 1], "15m")
        self.assertNotIn("vuln", " ".join(cmd))
        self.assertNotIn("exploit", " ".join(cmd))
        self.assertNotIn("dos", " ".join(cmd).lower())

    def test_nuclei_guardrails(self):
        cfg = {
            "nuclei": {
                "rate_limit": 10,
                "concurrency": 5,
                "bulk_size": 5,
                "timeout_seconds": 8,
                "retries": 0,
                "tags": ["cve", "exposures", "misconfiguration", "technologies"],
                "exclude_tags": ["dos", "fuzz", "intrusive", "exploit", "bruteforce"],
                "exclude_types": ["headless", "code", "javascript"],
            }
        }
        cmd = _safe_nuclei_base("nuclei", cfg)
        joined = " ".join(cmd)
        self.assertIn("-ni", cmd)
        self.assertIn("-duc", cmd)
        self.assertIn("dos,fuzz,intrusive,exploit,bruteforce", joined)
        self.assertIn("headless,code,javascript", joined)
        self.assertIn("POST", joined)
        self.assertIn("DELETE", joined)
        self.assertEqual(cmd[cmd.index("-rl") + 1], "10")

    def test_no_shell_true_in_framework_source(self):
        root = Path(__file__).resolve().parents[1] / "reconfw"
        source = "\n".join(p.read_text(encoding="utf-8") for p in root.glob("*.py"))
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()
