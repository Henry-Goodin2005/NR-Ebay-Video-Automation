#!/usr/bin/env python3
"""
BCS-421 — upload NetSuite item videos to eBay's Media API.

Replaces the Celigo A2 step, which cannot carry binary.

Modes
-----
  python upload_video.py --test-netsuite
      Run the queue query and print what it finds. Changes nothing.

  python upload_video.py
      Batch: every item at status REGISTERED gets uploaded, then written
      back to UPLOADED (and LIVE if eBay finishes while we're watching).

  python upload_video.py <videoId> <fileUrl>
      Single item, manual. No NetSuite involved. This is the mode that
      proved the upload works on 2026-09-29.
"""
import os, sys, time, tempfile, requests

from dotenv import load_dotenv
load_dotenv()

from requests_oauthlib import OAuth1
from oauthlib.oauth1 import SIGNATURE_HMAC_SHA256

# ---------------------------------------------------------------- eBay ----

EBAY_TOKEN_URL = "https://api.ebay.com/identity/v1/oauth2/token"
MEDIA_BASE     = "https://apim.ebay.com/commerce/media/v1_beta"
SCOPE          = "https://api.ebay.com/oauth/api_scope/sell.inventory"

# ------------------------------------------------------------ NetSuite ----

NS_ACCOUNT = os.environ["NS_ACCOUNT"]                      # e.g. 7154584_SB2
NS_HOST    = NS_ACCOUNT.lower().replace("_", "-")          # 7154584-sb2
NS_REST    = f"https://{NS_HOST}.suitetalk.api.netsuite.com/services/rest"
NS_UI      = f"https://{NS_HOST}.app.netsuite.com"          # File Cabinet lives here

QUEUE_SQL = """
SELECT
    i.id                      AS item_id,
    i.itemid                  AS sku,
    i.custitem_nr_video_id    AS video_id,
    f.id                      AS file_id,
    f.name                    AS file_name,
    f.filesize                AS file_size,
    f.url                     AS file_url
FROM item i
JOIN file f ON f.id = i.custitem_nr_video
WHERE i.custitem_nr_video_status = 'REGISTERED'
  AND i.custitem_nr_video_id IS NOT NULL
"""
# NOTE: do not add `AND custitem_nr_video_id != ''` here. SuiteQL is Oracle,
# Oracle treats '' as NULL, so that comparison is never true and silently
# returns zero rows without erroring. IS NOT NULL already covers it.


def ns_auth():
    """OAuth 1.0a / HMAC-SHA256, the way NetSuite's TBA wants it."""
    return OAuth1(
        client_key=os.environ["NS_CONSUMER_KEY"],
        client_secret=os.environ["NS_CONSUMER_SECRET"],
        resource_owner_key=os.environ["NS_TOKEN_ID"],
        resource_owner_secret=os.environ["NS_TOKEN_SECRET"],
        signature_method=SIGNATURE_HMAC_SHA256,
        realm=NS_ACCOUNT.upper(),
    )


def ns_queue():
    """
    Items sitting at REGISTERED, with the File Cabinet URL and real byte count.

    Timeout is generous on purpose. This query joins item -> file, and under
    a scoped role NetSuite evaluates row-level permissions across the whole
    File Cabinet (~724k rows in SB2). The status filter keeps it selective in
    practice, but an unfiltered scan of that table times out at 90s, so there
    is no margin to be clever with here.
    """
    r = requests.post(
        f"{NS_REST}/query/v1/suiteql",
        auth=ns_auth(),
        headers={"Content-Type": "application/json", "Prefer": "transient"},
        json={"q": QUEUE_SQL},
        timeout=180,
    )
    if r.status_code != 200:
        print(f"SuiteQL -> HTTP {r.status_code}\n{r.text[:1000]}")
        r.raise_for_status()
    return r.json().get("items", [])


def ns_scalar(sql, timeout=90):
    """
    Run a COUNT query, return the number or a readable reason it failed.

    Never raises: one slow or forbidden query shouldn't stop the ladder,
    because the point is to see which rung breaks.
    """
    try:
        r = requests.post(
            f"{NS_REST}/query/v1/suiteql",
            auth=ns_auth(),
            headers={"Content-Type": "application/json", "Prefer": "transient"},
            json={"q": sql},
            timeout=timeout,
        )
    except requests.exceptions.ReadTimeout:
        return f"TIMEOUT after {timeout}s"
    except Exception as e:
        return f"{type(e).__name__}: {e}"

    if r.status_code != 200:
        return f"HTTP {r.status_code} {r.text[:160]}"
    items = r.json().get("items", [])
    return items[0].get("n") if items else 0


# Note the ROWNUM bounds on the "visible at all" checks. An unbounded
# COUNT(*) over 90k items or 724k files is slow under any role and very
# slow under a scoped one, because row-level permissions are evaluated
# per row. "Can this role see any at all" is a 1-or-0 question.
DIAGNOSTICS = [
    ("items visible at all",          "SELECT COUNT(*) AS n FROM item WHERE ROWNUM <= 1"),
    ("files visible at all",          "SELECT COUNT(*) AS n FROM file WHERE ROWNUM <= 1"),
    ("log record readable",           "SELECT COUNT(*) AS n FROM customrecord_nr_video_log "
                                      "WHERE ROWNUM <= 1"),
    ("items with a video file set",   "SELECT COUNT(*) AS n FROM item "
                                      "WHERE custitem_nr_video IS NOT NULL"),
    ("items with a video id",         "SELECT COUNT(*) AS n FROM item "
                                      "WHERE custitem_nr_video_id IS NOT NULL"),
    ("items at REGISTERED",           "SELECT COUNT(*) AS n FROM item "
                                      "WHERE custitem_nr_video_status = 'REGISTERED'"),
    ("item JOIN file",                "SELECT COUNT(*) AS n FROM item i "
                                      "JOIN file f ON f.id = i.custitem_nr_video"),
    ("the full queue query",          f"SELECT COUNT(*) AS n FROM ({QUEUE_SQL})"),
    ("item 136663 by id",             "SELECT COUNT(*) AS n FROM item WHERE id = 136663"),
    ("file 1040089 by id",            "SELECT COUNT(*) AS n FROM file WHERE id = 1040089"),
]


def ns_diagnose():
    """Walk the query from the outside in. The first zero is the culprit."""
    print("what this role can see:\n")
    for label, sql in DIAGNOSTICS:
        print(f"  {label:<30} {ns_scalar(sql)}")
    print()


def ns_query(sql):
    """Any SuiteQL query. Returns the rows."""
    r = requests.post(
        f"{NS_REST}/query/v1/suiteql",
        auth=ns_auth(),
        headers={"Content-Type": "application/json", "Prefer": "transient"},
        json={"q": sql},
        timeout=60,
    )
    if r.status_code != 200:
        print(f"SuiteQL -> HTTP {r.status_code}\n{r.text[:600]}")
        r.raise_for_status()
    return r.json().get("items", [])


def ns_set_fields(item_id, values, verify=True):
    """
    Write one or more fields back onto the item, then read them back.

    NetSuite's REST API returns 204 for writes it silently discards -- a
    field it will not expose, a permission it will not honour. A success
    code proves the request was accepted, not that anything changed. This
    has bitten this project three separate ways, so every write is checked.
    """
    r = requests.patch(
        f"{NS_REST}/record/v1/inventoryItem/{item_id}",
        auth=ns_auth(),
        headers={"Content-Type": "application/json"},
        json=values,
        timeout=60,
    )
    if r.status_code not in (200, 204):
        print(f"  ! write failed: HTTP {r.status_code} {r.text[:400]}")
        return False

    if not verify:
        return True

    cols = ", ".join(values.keys())
    try:
        back = ns_query(f"SELECT {cols} FROM item WHERE id = {int(item_id)}")
    except Exception as e:
        print(f"  ! wrote HTTP {r.status_code} but could not verify: {e}")
        return False

    row = back[0] if back else {}
    bad = []
    for field, wanted in values.items():
        got = row.get(field)
        if str(got) != str(wanted):
            bad.append(f"{field}: wanted {wanted!r}, found {got!r}")

    if bad:
        print(f"  ! NetSuite returned HTTP {r.status_code} but did not store:")
        for line in bad:
            print(f"      {line}")
        return False
    return True


def ebay_register(token, item_id):
    """
    Register a video with eBay and record the ID on the item.

    In production this is Celigo flow A1. It lives here so the pipeline can be
    tested end to end without a round trip through Celigo, and because it
    demonstrates the fix for A1's hardcoded `size`: the byte count comes from
    SuiteQL's item->file join, which the saved search could not produce.
    """
    rows = ns_query(f"""
        SELECT i.id AS item_id, i.itemid AS sku,
               f.id AS file_id, f.name AS file_name, f.filesize AS file_size
        FROM item i
        JOIN file f ON f.id = i.custitem_nr_video
        WHERE i.id = {int(item_id)}
    """)
    if not rows:
        sys.exit(f"item {item_id} has no video file attached (custitem_nr_video is empty)")

    row  = rows[0]
    size = int(row["file_size"])
    print(f"{row['sku']}  item {item_id}")
    print(f"  file {row['file_id']}  {row['file_name']}  {size:,} bytes")

    r = requests.post(
        f"{MEDIA_BASE}/video",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        json={
            "title": str(row["sku"])[:80],
            "description": f"NetSuite item {item_id} - {row['file_name']}",
            "size": size,                 # must be exact, or eBay returns 190007
            "classification": ["ITEM"],
        },
        timeout=60,
    )
    if r.status_code != 201:
        sys.exit(f"createVideo -> HTTP {r.status_code}: {r.text[:400]}")

    # The body is empty. The ID is only in the Location response header.
    location = r.headers.get("Location", "")
    video_id = location.rstrip("/").rsplit("/", 1)[-1]
    if len(video_id) != 32:
        sys.exit(f"could not read a video id from Location header: {location!r}")

    print(f"  registered {video_id}")
    ok = ns_set_fields(item_id, {
        "custitem_nr_video_id": video_id,
        "custitem_nr_video_status": "REGISTERED",
    })
    if not ok:
        sys.exit(
            f"\neBay registered video {video_id} but NetSuite did not store it.\n"
            f"That video id is now orphaned - it exists on eBay and nothing in\n"
            f"NetSuite points at it. Fix the write before retrying, or you will\n"
            f"leak a registered video every attempt."
        )
    print(f"  NetSuite: item {item_id} -> REGISTERED")
    return video_id


def ns_set_status(item_id, status, note=None):
    """
    Write the status back onto the item, and optionally the human-readable
    last result. The field is current state only — history lives in the log
    record, because a field is overwritten by the next run and the second
    failure would erase the first.
    """
    if not ns_set_fields(item_id, {"custitem_nr_video_status": status}):
        return False
    print(f"  NetSuite: item {item_id} -> {status}")

    # The note is a convenience, written separately and unverified on purpose.
    # It must never be able to fail a run or mask the status write, which is
    # the part that actually drives the pipeline.
    if note:
        ns_set_fields(item_id,
                      {"custitem_nr_video_last_result": str(note)[:290]},
                      verify=False)
    return True


def ns_log(item_id, video_id, result, message="", file_size=None):
    """
    One row per attempt in customrecord_nr_video_log.

    Best effort: a failed log write is reported but never fails the run. The
    upload is the job; the log is the record of it.
    """
    body = {
        "name": f"{result} - item {item_id}",
        "custrecord_nrvl_item": {"id": str(item_id)},
        "custrecord_nrvl_video_id": video_id or "",
        "custrecord_nrvl_result": result,
        "custrecord_nrvl_message": str(message)[:3900],
    }
    if file_size:
        body["custrecord_nrvl_file_size"] = int(file_size)

    try:
        r = requests.post(
            f"{NS_REST}/record/v1/customrecord_nr_video_log",
            auth=ns_auth(),
            headers={"Content-Type": "application/json"},
            json=body,
            timeout=60,
        )
        if r.status_code not in (200, 201, 204):
            print(f"  ! log write failed: HTTP {r.status_code} {r.text[:300]}")
            return False
        print(f"  logged: {result}")
        return True
    except Exception as e:
        print(f"  ! log write failed: {type(e).__name__}: {e}")
        return False


# ------------------------------------------------------------ eBay work ----

def get_access_token():
    """
    Prefer a token minted from the refresh token — that's what makes this
    runnable unattended. EBAY_ACCESS_TOKEN is the manual fallback we used
    while the refresh exchange was still returning 400.
    """
    try:
        r = requests.post(
            EBAY_TOKEN_URL,
            auth=(os.environ["EBAY_CLIENT_ID"], os.environ["EBAY_CLIENT_SECRET"]),
            data={
                "grant_type": "refresh_token",
                "refresh_token": os.environ["EBAY_REFRESH_TOKEN"],
                "scope": SCOPE,
            },
            timeout=30,
        )
        if r.status_code == 200:
            print("minted a fresh access token from the refresh token")
            return r.json()["access_token"]
        print(f"refresh exchange -> HTTP {r.status_code} {r.text[:300]}")
    except KeyError as e:
        print(f"refresh exchange skipped, {e} not in .env")

    token = os.environ.get("EBAY_ACCESS_TOKEN")
    if not token:
        sys.exit("No access token. Fix the refresh exchange or set EBAY_ACCESS_TOKEN.")
    print("falling back to EBAY_ACCESS_TOKEN (expires ~2h after it was minted)")
    return token


def download(url):
    """Pull the file from NetSuite's File Cabinet to a temp file."""
    tmp = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
    with requests.get(url, stream=True, timeout=300) as r:
        r.raise_for_status()
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            tmp.write(chunk)
    tmp.close()
    size = os.path.getsize(tmp.name)
    with open(tmp.name, "rb") as f:
        head = f.read(12)
        if b"ftyp" not in head:
            os.remove(tmp.name)
            raise SystemExit(
                f"That URL didn't return an MP4 (first bytes: {head!r}). "
                "Check the h= hash and that the file is Available Without Login."
            )
    print(f"  downloaded {size:,} bytes -> {tmp.name}")
    return tmp.name, size


def upload(token, video_id, path):
    with open(path, "rb") as f:
        r = requests.post(
            f"{MEDIA_BASE}/video/{video_id}/upload",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/octet-stream",
            },
            data=f,
            timeout=600,
        )
    print(f"  upload -> HTTP {r.status_code} {r.text[:300]}")
    r.raise_for_status()


def poll(token, video_id, attempts=20, delay=15):
    for i in range(attempts):
        r = requests.get(
            f"{MEDIA_BASE}/video/{video_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        r.raise_for_status()
        body = r.json()
        status = body.get("status")
        print(f"  [{i+1}/{attempts}] status={status}")
        if status == "LIVE":
            return body
        if status in ("BLOCKED", "REJECTED"):
            raise SystemExit(f"eBay rejected the video: {body}")
        time.sleep(delay)
    print("  still processing — not an error, just slow. A3 will catch it.")
    return None


UPLOADED_SQL = """
SELECT
    i.id                   AS item_id,
    i.itemid               AS sku,
    i.custitem_nr_video_id AS video_id
FROM item i
WHERE i.custitem_nr_video_status = 'UPLOADED'
  AND i.custitem_nr_video_id IS NOT NULL
"""


def ns_set_expiration(item_id, expires):
    """
    Write eBay's expirationDate onto the item.

    Written unverified on purpose: eBay returns ISO 8601
    ('2026-11-06T19:54:56Z') and NetSuite stores and returns date/time
    fields in its own display format, so a string read-back would always
    look like a mismatch even on a successful write.
    """
    if not expires:
        return
    ns_set_fields(item_id,
                  {"custitem_nr_video_expiration": expires},
                  verify=False)


def reconcile(token, rows):
    """
    Pick up anything left at UPLOADED by an earlier run.

    A single run polls for five minutes. eBay allows up to 48 hours to
    process a video, and up to seven business days when a review queue is
    backed up. Without this pass, a video that outlasts its own run would
    sit at UPLOADED forever: nothing would move it to LIVE, and the item
    would list with no video and no error anywhere.

    This is what the planned Celigo flow A3 was for. It lives here instead
    because this script already runs on a schedule and already has the
    polling code, so a third flow and a second schedule would be two more
    things to maintain for the same outcome. It also covers a case A3 could
    not: a run that dies after the upload but before the poll.
    """
    if not rows:
        return

    print(f"{len(rows)} item(s) left at UPLOADED from an earlier run")
    for row in rows:
        item_id  = row["item_id"]
        video_id = row["video_id"]
        sku      = row.get("sku")
        try:
            r = requests.get(
                f"{MEDIA_BASE}/video/{video_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            r.raise_for_status()
            body   = r.json()
            status = body.get("status")
            print(f"  {sku}  item={item_id}  eBay says {status}")

            if status == "LIVE":
                expires = body.get("expirationDate", "")
                ns_set_status(item_id, "LIVE", f"live on eBay, expires {expires}")
                ns_set_expiration(item_id, expires)
                ns_log(item_id, video_id, "LIVE", f"expires {expires} (reconciled)")

            elif status in ("BLOCKED", "PROCESSING_FAILED", "REJECTED"):
                ns_set_status(item_id, "UPLOAD_FAILED", f"eBay reports {status}")
                ns_log(item_id, video_id, "FAILED", f"eBay reports {status}")

            # Still PROCESSING: leave it alone, try again tomorrow.

        except Exception as e:
            print(f"  ! {sku} item={item_id}: {type(e).__name__}: {e}")
    print()


def process(token, item):
    """One item, end to end. Returns True if eBay accepted the bytes."""
    item_id  = item["item_id"]
    video_id = item["video_id"]
    file_url = item["file_url"]
    if file_url.startswith("/"):
        file_url = NS_UI + file_url

    size_ns = int(item.get("file_size") or 0)
    print(f"\n{item.get('sku')}  item={item_id}  video={video_id}")
    print(f"  {item.get('file_name')}  ({size_ns:,} bytes per NetSuite)")

    path = None
    try:
        path, size = download(file_url)
        upload(token, video_id, path)

        ns_set_status(item_id, "UPLOADED", "bytes accepted by eBay, processing")
        ns_log(item_id, video_id, "UPLOADED", "bytes accepted by eBay", size)

        result = poll(token, video_id)
        if result:
            expires = result.get("expirationDate", "")
            ns_set_status(item_id, "LIVE", f"live on eBay, expires {expires}")
            ns_set_expiration(item_id, expires)
            ns_log(item_id, video_id, "LIVE", f"expires {expires}", size)
        else:
            ns_log(item_id, video_id, "UPLOADED",
                   "still PROCESSING when the run ended - A3 will confirm", size)
        return True

    except Exception as e:
        ns_set_status(item_id, "UPLOAD_FAILED", str(e))
        ns_log(item_id, video_id, "FAILED", str(e), size_ns)
        raise
    finally:
        if path and os.path.exists(path):
            os.remove(path)


# ---------------------------------------------------------------- main ----

if __name__ == "__main__":
    args = sys.argv[1:]

    if args == ["--diagnose"]:
        ns_diagnose()
        sys.exit(0)

    if args == ["--reconcile"]:
        stragglers = ns_query(UPLOADED_SQL)
        if not stragglers:
            print("nothing at UPLOADED")
            sys.exit(0)
        reconcile(get_access_token(), stragglers)
        sys.exit(0)

    if args == ["--test-netsuite"]:
        rows = ns_queue()
        print(f"{len(rows)} item(s) at REGISTERED\n")
        for row in rows:
            print(f"  {row.get('sku')}  item={row['item_id']}  video={row['video_id']}")
            print(f"    file {row['file_id']}  {row.get('file_name')}  "
                  f"{int(row.get('file_size') or 0):,} bytes")
            print(f"    {row['file_url']}\n")
        sys.exit(0)

    if len(args) == 2 and args[0] == "--test-log":
        # Write one row and one field, nothing else. Proves the plumbing
        # before a real run depends on it.
        item_id = args[1]
        marker  = f"test write {int(time.time())}"

        ns_set_status(item_id, "REGISTERED", marker)
        ok_row = ns_log(item_id, "0" * 32, "TEST", "test row from --test-log", 12345)

        # Read it back. HTTP 204 only means NetSuite accepted the request --
        # it silently discards fields it will not write, so a success code
        # proves nothing about whether the value landed.
        back = ns_query(f"""
            SELECT custitem_nr_video_status AS st,
                   custitem_nr_video_last_result AS note
            FROM item WHERE id = {int(item_id)}
        """)
        got_status = (back[0].get("st")   if back else None)
        got_note   = (back[0].get("note") if back else None)

        print(f"\nstatus field : {'ok' if got_status == 'REGISTERED' else 'FAILED'}"
              f"  (read back: {got_status!r})")
        print(f"result field : {'ok' if got_note == marker else 'FAILED'}"
              f"  (read back: {got_note!r})")
        print(f"log row      : {'ok' if ok_row else 'FAILED'}")

        if got_note != marker:
            print("\n  The result field did not store. Check the field record:")
            print("    Applies To  -> Inventory Item ticked")
            print("    Store Value -> ticked")
            print("    Display Type-> Normal, not Disabled or Inline Text")

        sys.exit(0 if (got_status == "REGISTERED" and got_note == marker and ok_row) else 1)

    if len(args) == 2 and args[0] == "--register":
        ebay_register(get_access_token(), args[1])
        sys.exit(0)

    if len(args) == 3 and args[0] == "--set-status":
        ok = ns_set_status(args[1], args[2])
        sys.exit(0 if ok else 1)

    if len(args) == 2:                       # manual single-item mode
        video_id, file_url = args
        token = get_access_token()
        path, size = download(file_url)
        print(f"uploading {size:,} bytes to video {video_id}")
        try:
            upload(token, video_id, path)
        finally:
            os.remove(path)
        result = poll(token, video_id)
        if result:
            print("LIVE — expires", result.get("expirationDate"))
        sys.exit(0)

    if args:
        sys.exit(__doc__)

    rows       = ns_queue()                   # batch mode
    stragglers = ns_query(UPLOADED_SQL)

    if not rows and not stragglers:
        print("nothing at REGISTERED or UPLOADED — nothing to do")
        sys.exit(0)

    token = get_access_token()

    # Clear the backlog before taking on new work. If eBay is slow or down,
    # yesterday's items are the ones closest to being finished.
    reconcile(token, stragglers)

    if not rows:
        sys.exit(0)

    print(f"{len(rows)} item(s) to upload")
    failures = 0
    for row in rows:
        try:
            process(token, row)
        except Exception as e:
            failures += 1
            print(f"  ! {type(e).__name__}: {e}")
    print(f"\ndone — {len(rows) - failures} succeeded, {failures} failed")
    sys.exit(1 if failures else 0)
