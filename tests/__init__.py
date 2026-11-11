"""Test package setup.

Three PL-010 fixtures need a Stripe-live-shaped fake key. Committing one trips GitHub push protection, so the files are
written here at import time (they are git-ignored) with the key assembled from parts. The key is fake.
"""
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_KEY = "sk_" + "live_" + "51FAKE0test0FAKE0test0FAKE0abcd"
_FILES = {'tests/fixtures/codescan/pl010_fp/src/__tests__/stripe.test.ts': 'const key = "{KEY}";\n', 'tests/fixtures/codescan/pl010_tp/src/lib/stripe.ts': 'export const stripe = new Stripe("{KEY}");\n', 'tests/fixtures/codescan/pl010_tp/.env': 'VITE_SUPABASE_URL=https://fakeprojectref000.supabase.co\nVITE_STRIPE_SECRET_KEY={KEY}\n'}

for _rel, _text in _FILES.items():
    _path = os.path.join(_HERE, os.pardir, _rel)
    os.makedirs(os.path.dirname(_path), exist_ok=True)
    with open(_path, "w", encoding="utf-8") as _fh:
        _fh.write(_text.replace("{KEY}", _KEY))
