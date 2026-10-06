#!/usr/bin/env python3
"""
BCS-421 — work out which half of the eBay credentials is wrong.

Prints no secret values. Safe to paste the output anywhere.

    python check_ebay_auth.py
"""
import os, requests
from dotenv import load_dotenv

load_dotenv()

TOKEN_URL = "https://api.ebay.com/identity/v1/oauth2/token"
SCOPE     = "https://api.ebay.com/oauth/api_scope/sell.inventory"

EXPECTED = [
    "EBAY_CLIENT_ID", "EBAY_CLIENT_SECRET", "EBAY_REFRESH_TOKEN",
    "NS_ACCOUNT", "NS_CONSUMER_KEY", "NS_CONSUMER_SECRET",
    "NS_TOKEN_ID", "NS_TOKEN_SECRET",
]

print("variables present in .env:\n")
for name in EXPECTED:
    v = os.environ.get(name)
    print(f"  {name:<22} {'set, ' + str(len(v)) + ' chars' if v else 'MISSING'}")

extra = os.environ.get("EBAY_ACCESS_TOKEN")
if extra:
    print(f"  {'EBAY_ACCESS_TOKEN':<22} set — delete this once the refresh flow works")

cid    = os.environ.get("EBAY_CLIENT_ID")
secret = os.environ.get("EBAY_CLIENT_SECRET")
refresh = os.environ.get("EBAY_REFRESH_TOKEN")

if not (cid and secret):
    raise SystemExit("\nNo client id/secret — nothing to test.")

# A refresh token starts r^1 and runs ~450-500 chars. An access token starts
# r^0 and is a multi-thousand-character gzipped blob. Both come back in the
# same JSON response, so the wrong one ends up here often.
wrong_token_type = False
if refresh:
    if "r^1" in refresh[:40]:
        print("\n  EBAY_REFRESH_TOKEN looks correct (r^1)")
    elif "r^0" in refresh[:40]:
        wrong_token_type = True
        print(f"\n  !! EBAY_REFRESH_TOKEN contains r^0 and is {len(refresh)} chars.")
        print("     That is an ACCESS token, not a refresh token.")
        print("     A refresh token starts r^1 and is roughly 450-500 chars.")
    else:
        print("\n  EBAY_REFRESH_TOKEN format unrecognised")

# --- test 1: are the client id and secret a valid pair at all? -------------
# client_credentials needs no refresh token, so it isolates the keyset.
print("\n[1] testing client id + secret on their own (client_credentials grant)")
r = requests.post(
    TOKEN_URL,
    auth=(cid, secret),
    data={"grant_type": "client_credentials",
          "scope": "https://api.ebay.com/oauth/api_scope"},
    timeout=30,
)
if r.status_code == 200:
    print("    OK — this App ID and Cert ID are a valid pair.")
else:
    print(f"    FAILED HTTP {r.status_code}: {r.text[:300]}")
    print("    The client id and secret don't go together. Everything else is moot.")
    raise SystemExit(1)

# --- test 2: does the refresh token belong to that pair? -------------------
if not refresh:
    raise SystemExit("\nNo EBAY_REFRESH_TOKEN set — run the authorization code grant.")

print("\n[2] testing the refresh token against that same pair")
r = requests.post(
    TOKEN_URL,
    auth=(cid, secret),
    data={"grant_type": "refresh_token", "refresh_token": refresh, "scope": SCOPE},
    timeout=30,
)
if r.status_code == 200:
    token = r.json().get("access_token", "")
    expires = r.json().get("expires_in")
    print(f"    OK — minted an access token ({len(token)} chars, expires in {expires}s).")
    print("\nAuth is fixed. Delete EBAY_ACCESS_TOKEN from .env and run the uploader.")
else:
    print(f"    FAILED HTTP {r.status_code}: {r.text[:300]}")
    print("\n    Test 1 passed and test 2 failed, so the keyset is fine and the")
    print("    refresh token belongs to a different one. Re-run the authorization")
    print("    code grant using THIS App ID, and replace EBAY_REFRESH_TOKEN.")
