"""Regression checks for the pinned accumulator-immediate identity map."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import generate_accumulator_immediates as generator


class AccumulatorImmediateGeneratorTests(unittest.TestCase):
    def test_all_candidate_ids_partition_into_supported_and_reason_coded_modes(self) -> None:
        rendered = generator.render()
        self.assertEqual(rendered, generator.render())
        self.assertEqual(rendered.count("AccumulatorImmediateForm {"), 90)
        self.assertEqual(rendered.count("UnsupportedAccumulatorIdentity {"), 108)
        self.assertIn("IMM8_MAPPED_COUNT: usize = 27", rendered)
        self.assertIn("SIMMZ_MAPPED_COUNT: usize = 63", rendered)
        self.assertIn("ACCUMULATOR_UNSUPPORTED_COUNT: usize = 108", rendered)

    def test_catalogue_digest_pin_rejects_mutated_candidates(self) -> None:
        changed_pin = (generator.SOURCES[0][0], 63, "0" * 64)
        with patch.object(generator, "SOURCES", (changed_pin, *generator.SOURCES[1:])):
            with self.assertRaisesRegex(ValueError, "catalogue digest changed"):
                generator.render()


if __name__ == "__main__":
    unittest.main()
