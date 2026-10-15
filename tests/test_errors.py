import unittest

from mtd_ring.errors import (
    DuplicateHoneypotError,
    InvalidDirectionError,
    IsolatedHoneypotError,
    NegativeTimeError,
    RingError,
    UnknownHoneypotError,
)


class ErrorCodesTest(unittest.TestCase):
    def test_every_error_is_a_ring_error_with_its_own_code(self):
        errors = [
            DuplicateHoneypotError("HP-1"),
            UnknownHoneypotError("HP-1"),
            InvalidDirectionError(),
            IsolatedHoneypotError("HP-1"),
            NegativeTimeError(),
        ]
        self.assertTrue(all(isinstance(error, RingError) for error in errors))
        codes = [error.code for error in errors]
        self.assertEqual(len(set(codes)), len(codes))

    def test_errors_about_a_honeypot_carry_its_id(self):
        for error in (DuplicateHoneypotError("HP-7"), UnknownHoneypotError("HP-7"), IsolatedHoneypotError("HP-7")):
            self.assertEqual(error.params, {"id": "HP-7"})

    def test_errors_without_context_have_empty_params(self):
        self.assertEqual(InvalidDirectionError().params, {})
        self.assertEqual(NegativeTimeError().params, {})


if __name__ == "__main__":
    unittest.main()
