import unittest

from backend.integrations.sso_checker import (
    BotFlagInfo,
    SsoChecker,
    SsoCredential,
    SsoVerdict,
)


class _Cookies:
    def set(self, *args, **kwargs):
        return None


class _Response:
    status_code = 200
    url = "https://grok.com/"

    def __init__(self, source):
        source_json = "null" if source is None else str(source)
        self.text = (
            '<script>self.__next_f.push([1,"'
            '\\"initialData\\":{\\"user\\":{'
            '\\"email\\":\\"fixture@example.com\\",'
            '\\"userId\\":\\"fixture-user\\",'
            f'\\"botFlagSource\\":{source_json}'
            '}}"])</script>'
        )


class _Session:
    def __init__(self, source):
        self.cookies = _Cookies()
        self.source = source
        self.proxies = {}

    def get(self, *args, **kwargs):
        return _Response(self.source)


class SsoCheckerTests(unittest.TestCase):
    def test_bot_flag_zero_is_clean_and_every_nonzero_value_is_flagged(self):
        self.assertFalse(BotFlagInfo(found=True, source=0).is_flagged())
        self.assertFalse(BotFlagInfo(found=True, source=0, denied=True).is_flagged())
        for source in (1, 2, 3, -1):
            with self.subTest(source=source):
                self.assertTrue(BotFlagInfo(found=True, source=source).is_flagged())

    def test_null_source_is_invalid_or_unknown_and_token_is_not_serialized(self):
        token = "fixture-sensitive-sso-token"
        checker = SsoChecker(session_factory=lambda: _Session(None))
        result = checker.check(
            SsoCredential(token, expected_email="fixture@example.com")
        )
        serialized = result.to_dict()

        self.assertEqual(result.verdict, SsoVerdict.INVALID_OR_UNKNOWN)
        self.assertTrue(result.valid_session)
        self.assertIsNone(result.bot_flag.source)
        self.assertNotIn(token, repr(result))
        self.assertNotIn(token, str(serialized))

    def test_zero_source_is_clean(self):
        checker = SsoChecker(session_factory=lambda: _Session(0))
        result = checker.check(
            SsoCredential("fixture-token", expected_email="fixture@example.com")
        )
        self.assertEqual(result.verdict, SsoVerdict.CLEAN)

    def test_nonzero_source_is_flagged(self):
        for source in (1, 2, 3, -1):
            with self.subTest(source=source):
                checker = SsoChecker(session_factory=lambda source=source: _Session(source))
                result = checker.check(SsoCredential("fixture-token"))
                self.assertEqual(result.verdict, SsoVerdict.FLAGGED)


if __name__ == "__main__":
    unittest.main()
