"""
trace_forgot.py — where is /forgot defined on a JS-heavy target?

Run locally (from a network that can reach the target):
    python scripts/trace_forgot.py https://ntaa.com.au /forgot

It fetches the homepage, finds every .js bundle it references, follows one
level of chunk imports, and reports which file (if any) contains the route
string. That tells you whether Katana *could* have mined it (main/preloaded
bundle) or never saw it (lazy-loaded chunk not linked from the entry).
"""
import re
import sys
import httpx
from urllib.parse import urljoin

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

target = sys.argv[1] if len(sys.argv) > 1 else "https://ntaa.com.au"
needle = sys.argv[2] if len(sys.argv) > 2 else "/forgot"

JS_REF = re.compile(r"""["'`]([^"'`\s<>]+?\.(?:js|mjs))(?:\?[^"'`]*)?["'`]""", re.I)
ATTR   = re.compile(r"""(?:src|href)\s*=\s*["']([^"'#\s]+\.(?:js|mjs)[^"']*)["']""", re.I)

c = httpx.Client(follow_redirects=True, timeout=30, headers={"User-Agent": UA})


def get(url):
    try:
        r = c.get(url)
        return r.text if r.status_code < 400 else None
    except Exception as e:
        print(f"  ! {url} -> {type(e).__name__}")
        return None


def scan(url, label):
    body = get(url)
    if body is None:
        return set()
    hit = needle.lower() in body.lower()
    print(f"[{'HIT ' if hit else '    '}] {label}: {url}  ({len(body):,} bytes)")
    if hit:
        # show a little context around the first match
        i = body.lower().find(needle.lower())
        print("        …" + body[max(0, i - 60):i + 60].replace("\n", " ") + "…")
    # return .js references found inside this body
    refs = set(JS_REF.findall(body)) | set(ATTR.findall(body))
    return {urljoin(url, r) for r in refs}

# 1) homepage → entry bundles
entry = scan(target, "homepage HTML")

# 2) each entry bundle → its imported chunks (one level, deduped)
seen = set()
chunks = set()
for js in sorted(entry):
    if js in seen:
        continue
    seen.add(js)
    chunks |= scan(js, "entry bundle")

# 3) the next level of chunks (lazy route chunks usually live here)
for js in sorted(chunks - seen):
    seen.add(js)
    scan(js, "chunk")

print(f"\nScanned {len(seen)} JS file(s). If '{needle}' only appears in a chunk "
      "NOT linked from the homepage/entry bundle, Katana's miner never saw it — "
      "that's a lazy-loaded route chunk, and why the endpoint was missed.")
