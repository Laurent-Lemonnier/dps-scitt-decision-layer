"""Focused local candidate tests; use the unchanged v0.28.0 corpus as input.

GILDA_CORPUS=/path/to/vectors-agent-audit-record python3 -m unittest discover \
    -s interop/gilda -p 'test_gilda_aggregation.py' -v
"""
import contextlib
import copy
import io
import itertools
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import gilda_verify_independent as g


class AggregationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = Path(os.environ["GILDA_CORPUS"])
        cls.manifest = json.loads((cls.corpus / "MANIFEST.json").read_text())
        cls.fr14 = next(v for v in cls.manifest["vectors"] if v["draftId"] == "FR14")
        cls.raw = (cls.corpus / cls.fr14["file"]).read_bytes()
        cls.keys = {v["keyid"]: bytes.fromhex(v["publicKey"]) for v in cls.manifest["keys"].values()}

    def record(self):
        rep = g.verify_envelope(json.loads(self.raw), self.keys)
        self.assertEqual(rep.verdict, "valid")
        return rep

    def run_fr14(self, vector):
        """Run the real judge over a temporary one-member manifest, same bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = dict(self.manifest, vectors=[vector])
            (root / "MANIFEST.json").write_text(json.dumps(manifest))
            envelope = root / vector["file"]
            envelope.parent.mkdir(parents=True)
            envelope.write_bytes(self.raw)
            with contextlib.redirect_stdout(io.StringIO()):
                code = g.judge(str(root), str(root / "report.json"))
            self.assertEqual(envelope.read_bytes(), self.raw)
            return code, json.loads((root / "report.json").read_text())

    def test_fr14_recomputes_whole_pair_and_matches_signed_entry(self):
        code, report = self.run_fr14(self.fr14)
        row = report["rows"][0]
        self.assertEqual(code, 0)
        self.assertEqual(row["got"], "valid")
        self.assertEqual(row["aggregation"]["status"], "match")
        self.assertEqual(row["aggregation"]["selected"],
                         {"lastResult": "2026-09-19T11:03:32Z", "maxAge": 60})
        self.assertEqual(row["aggregation"]["selected"], row["aggregation"]["carried"])

    def test_fr14_permutations(self):
        for values in itertools.permutations(self.fr14["aggregation"]["values"]):
            with self.subTest(values=values):
                vector = copy.deepcopy(self.fr14)
                vector["aggregation"]["values"] = list(values)
                code, report = self.run_fr14(vector)
                self.assertEqual(code, 0)
                self.assertEqual(report["rows"][0]["aggregation"]["status"], "match")

    def test_source_only_mutation_fails_correspondence_not_record(self):
        vector = copy.deepcopy(self.fr14)
        vector["aggregation"]["values"][1]["maxAge"] = 3601
        # Both values remain fresh, but B now expires first: 11:04:03Z.
        at = g.aggregation_time(vector["aggregation"]["reportedAt"])
        for value in vector["aggregation"]["values"]:
            self.assertLessEqual(at - g.aggregation_time(value["lastResult"]), value["maxAge"])
        code, report = self.run_fr14(vector)
        row = report["rows"][0]
        self.assertEqual(code, 1)
        self.assertEqual(report["agree"], 1)
        self.assertEqual(row["got"], "valid")
        self.assertEqual(row["codes"], [])
        self.assertEqual(row["aggregation"]["status"], "mismatch")
        self.assertEqual(row["aggregation"]["selected"],
                         {"lastResult": "2026-09-19T10:04:02Z", "maxAge": 3601})
        self.assertEqual((self.corpus / self.fr14["file"]).read_bytes(), self.raw)
        self.record()  # Includes real signature verification, unchanged bytes.

    def test_historical_independent_minima_fails_fr14(self):
        def independent_minima(values):
            return {"lastResult": min(v["lastResult"] for v in values),
                    "maxAge": min(v["maxAge"] for v in values)}
        with mock.patch.object(g, "select_aggregation_pair", independent_minima):
            code, report = self.run_fr14(self.fr14)
        row = report["rows"][0]
        self.assertEqual(code, 1)
        self.assertEqual(row["got"], "valid")
        self.assertEqual(row["aggregation"]["status"], "mismatch")
        self.assertEqual(row["aggregation"]["selected"],
                         {"lastResult": "2026-09-19T10:04:02Z", "maxAge": 60})

    def test_equal_expiry_uses_earlier_last_result(self):
        a = {"lastResult": "2026-09-19T11:03:32Z", "maxAge": 60}
        b = {"lastResult": "2026-09-19T11:03:02Z", "maxAge": 90}
        for values in ([a, b], [b, a]):
            self.assertEqual(g.select_aggregation_pair(values), b)

    def test_never_held_uses_smallest_bound_among_never_held_only(self):
        values = [{"lastResult": "none", "maxAge": 70},
                  {"lastResult": "2026-09-19T11:03:32Z", "maxAge": 1},
                  {"lastResult": "none", "maxAge": 50}]
        for order in itertools.permutations(values):
            self.assertEqual(g.select_aggregation_pair(list(order)),
                             {"lastResult": "none", "maxAge": 50})

    def test_exact_fractional_seconds_and_large_age(self):
        earlier = {"lastResult": "2026-09-19T11:03:32.0000001Z", "maxAge": 60}
        later = {"lastResult": "2026-09-19T11:03:32.0000002Z", "maxAge": 60}
        self.assertEqual(g.select_aggregation_pair([later, earlier]), earlier)
        large = {"lastResult": "2026-09-19T11:03:32Z", "maxAge": 2**53 - 1}
        self.assertEqual(g.select_aggregation_pair([large]), large)

    def test_equivalent_offset_matches(self):
        agg = copy.deepcopy(self.fr14["aggregation"])
        agg["values"][0]["lastResult"] = "2026-09-19T12:03:32+01:00"
        agg["reportedAt"] = "2026-09-19T12:04:02+01:00"
        self.assertEqual(g.check_aggregation(self.record(), agg)["status"], "match")

    def test_invalid_sources_do_not_pass_or_change_record_verdict(self):
        cases = [None, {}, [], {"input": "standing-source"}]
        for values in ([], None, [None], [{"lastResult": "none", "maxAge": True}],
                       [{"lastResult": "none", "maxAge": -1}],
                       [{"lastResult": "none", "maxAge": 2**53}],
                       [{"lastResult": "bad-date", "maxAge": 1}]):
            cases.append(dict(self.fr14["aggregation"], values=values))
        for agg in cases:
            with self.subTest(aggregation=agg):
                rep = self.record()
                self.assertEqual(g.check_aggregation(rep, agg)["status"], "invalid-input")
                self.assertEqual(rep.verdict, "valid")

    def test_binds_reference_time_input_and_both_pair_fields(self):
        for field, value in (("reportedAt", "2026-09-19T11:04:03Z"),
                             ("input", "policy-source")):
            agg = dict(self.fr14["aggregation"], **{field: value})
            self.assertEqual(g.check_aggregation(self.record(), agg)["status"], "mismatch")
        agg = copy.deepcopy(self.fr14["aggregation"])
        agg["values"][0]["maxAge"] = 59
        self.assertEqual(g.check_aggregation(self.record(), agg)["status"], "mismatch")

    def test_absent_sources_are_not_applicable(self):
        vector = copy.deepcopy(self.fr14)
        del vector["aggregation"]
        code, report = self.run_fr14(vector)
        self.assertEqual(code, 0)
        self.assertEqual(report["aggregationMembers"], 0)
        self.assertEqual(report["rows"][0]["aggregation"]["status"], "not-applicable")

    def test_bad_signature_is_not_compared_as_a_valid_record(self):
        env = json.loads(self.raw)
        env["signatures"][0]["sig"] = "AA=="
        rep = g.verify_envelope(env, self.keys)
        self.assertEqual(rep.verdict, "malformed")
        self.assertEqual(g.check_aggregation(rep, self.fr14["aggregation"])["status"], "not-checked")


if __name__ == "__main__":
    unittest.main()
