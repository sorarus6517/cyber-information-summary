#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE情報の取得(v0.1)

data/items.json に出てくるCVE番号を集め、NVD(米国国立脆弱性データベース)の
公開APIから深刻度・脆弱性の種類・影響を受ける製品を取得して
data/cve.json に貯める。

・一度取得したCVEは貯めておき、次回以降は取りに行かない(APIに優しく、速い)
・APIキーは使わない。無料の公開枠は「30秒間に5回」なので、7秒あけて順に叩く
・1回の実行で取りに行く件数には上限を設け、実行時間が延びないようにする

NVDのデータは米国著作権法第17編により public domain だが、
利用するサービスは次の表示を求められている(ページ側で表示する):
  "This product uses data from the NVD API but is not endorsed or certified by the NVD."
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
ITEMS_PATH = os.path.join(DATA_DIR, "items.json")
CVE_PATH = os.path.join(DATA_DIR, "cve.json")

API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
UA = "cyber-information-summary/0.1 (+https://cyber-information-summary.pages.dev)"

SLEEP = 7.0          # 秒。公開枠は30秒に5回なので6秒でも足りるが余裕を持たせる
MAX_NEW = 30         # 1回の実行で新しく取りに行く最大件数
MAX_REFRESH = 5      # 1回の実行で取り直す最大件数
REFRESH_AFTER = 30   # 日。これより古いキャッシュは取り直しの候補にする
RECENT_DAYS = 180    # 日。公表がこれより新しいCVEだけ取り直す(古いものは変わらない)
TIMEOUT = 30

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def log(msg):
    print(msg, flush=True)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def to_dt(s):
    if not s:
        return None
    try:
        s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def collect_cve_ids(items):
    """新しい項目のCVEから先に処理されるよう、登場順で重複を除いて返す。"""
    seen = []
    known = set()
    for it in items:
        text = " ".join([it.get("title") or "", it.get("title_ja") or "",
                         it.get("url") or ""])
        for cid in CVE_RE.findall(text.upper()):
            if cid not in known:
                known.add(cid)
                seen.append(cid)
    return seen


def pick_metric(metrics):
    """CVSSは複数入っていることがある。日本で通りのよい v3.1 を優先する。"""
    order = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]
    for key in order:
        arr = metrics.get(key) or []
        if not arr:
            continue
        m = arr[0]
        d = m.get("cvssData") or {}
        score = d.get("baseScore")
        if score is None:
            continue
        return {
            "version": str(d.get("version") or key),
            "score": score,
            "severity": d.get("baseSeverity") or m.get("baseSeverity") or "",
            "vector": d.get("vectorString") or "",
        }
    return None


def parse_products(cve, desc=""):
    """影響を受ける製品を (ベンダー, 製品) で返す。

    NVDのCPE一覧は、その製品を同梱している他社製品まで含むことがある
    (例: ISC BIND の脆弱性に Juniper の機器が延々と並ぶ)。
    説明文に出てくるベンダー・製品名を先に並べ替えて、本来の対象が
    先頭に来るようにする。
    """
    out = []
    seen = set()
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(parts) > 4 and parts[0] == "cpe":
                    pair = (parts[3], parts[4])
                    if pair not in seen and all(pair):
                        seen.add(pair)
                        out.append(list(pair))

    low = (desc or "").lower()

    def rank(pair):
        vendor, product = pair
        v = vendor.replace("_", " ")
        p = product.replace("_", " ")
        hit = 0
        if v and v in low:
            hit -= 2
        if p and p in low:
            hit -= 2
        # 製品名の先頭語(windows_10_1607 → windows)でも拾う
        if p.split(" ")[0] in low:
            hit -= 1
        return hit

    out.sort(key=rank)
    return out[:20]


def fetch(cve_id):
    req = urllib.request.Request(API % cve_id, headers={"User-Agent": UA,
                                                        "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = json.loads(r.read().decode("utf-8"))

    vulns = data.get("vulnerabilities") or []
    now = datetime.now(timezone.utc).isoformat()
    if not vulns:
        return {"fetched_at": now, "found": False}

    cve = vulns[0].get("cve") or {}
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break

    rec = {
        "fetched_at": now,
        "found": True,
        "id": cve.get("id") or cve_id,
        "published": cve.get("published") or "",
        "last_modified": cve.get("lastModified") or "",
        "status": cve.get("vulnStatus") or "",
        "desc_en": desc,
        "cwe": [],
        "products": parse_products(cve, desc),
    }
    metric = pick_metric(cve.get("metrics") or {})
    if metric:
        rec["cvss"] = metric
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value") or ""
            if v.startswith("CWE-") and v not in rec["cwe"]:
                rec["cwe"].append(v)
    rec["cwe"] = rec["cwe"][:3]
    return rec


def main():
    data = load_json(ITEMS_PATH, None)
    if not data:
        log("items.json が読めません")
        return 1
    ids = collect_cve_ids(data.get("items") or [])
    cache = load_json(CVE_PATH, {}).get("cves", {})
    now = datetime.now(timezone.utc)

    new_ids = [c for c in ids if c not in cache]

    refresh = []
    for cid in ids:
        rec = cache.get(cid)
        if not rec or not rec.get("found"):
            continue
        got = to_dt(rec.get("fetched_at"))
        pub = to_dt(rec.get("published"))
        if not got or now - got < timedelta(days=REFRESH_AFTER):
            continue
        if pub and now - pub > timedelta(days=RECENT_DAYS):
            continue          # 古いCVEはもう変わらないので取り直さない
        refresh.append(cid)

    todo = new_ids[:MAX_NEW] + refresh[:MAX_REFRESH]
    log("CVE: 全%d件 / 未取得%d件 / 取り直し候補%d件 → 今回%d件を取得"
        % (len(ids), len(new_ids), len(refresh), len(todo)))

    ok = err = 0
    for i, cid in enumerate(todo):
        if i:
            time.sleep(SLEEP)
        try:
            cache[cid] = fetch(cid)
            ok += 1
            log("  %s %s" % (cid, "取得" if cache[cid].get("found") else "該当なし"))
        except urllib.error.HTTPError as e:
            err += 1
            log("  %s HTTPエラー %s" % (cid, e.code))
            if e.code in (403, 429):
                log("  制限に当たったため今回はここで打ち切ります")
                break
        except Exception as e:
            err += 1
            log("  %s 取得できず: %s" % (cid, e))

    # items.json から消えたCVEは貯めたままにしておく(再取得を避けるため)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CVE_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": now.isoformat(), "cves": cache},
                  f, ensure_ascii=False, indent=1, sort_keys=True)

    found = sum(1 for v in cache.values() if v.get("found"))
    log("cve.json: 保存%d件(うち情報あり%d件) / 成功%d・失敗%d"
        % (len(cache), found, ok, err))
    return 0


if __name__ == "__main__":
    sys.exit(main())
