#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
規制・当局アップデート横断ビューア — 収集スクリプト(v0.2)

v0.1からの変更点
・CISAはRSSが取得できないことがあるため、公式のKEVカタログ(JSON)にも対応
・フィードに日付が入っていない場合は「確認日」として扱い、印を付ける
・取得時のヘッダーを調整(機械的なアクセスを弾くサイト対策)
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
ITEMS_PATH = os.path.join(DATA_DIR, "items.json")
TITLES_JA_PATH = os.path.join(DATA_DIR, "titles_ja.json")
STATUS_PATH = os.path.join(DATA_DIR, "status.json")

# 連絡先は自分のものに書き換えてください
CONTACT = "https://cyber-information-summary.pages.dev"
USER_AGENT = (
    "Mozilla/5.0 (compatible; RegWatchBot/0.2; +%s) "
    "personal non-commercial aggregator" % CONTACT
)
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/rss+xml, application/atom+xml, application/xml, "
              "text/xml, application/json;q=0.9, */*;q=0.8",
    "Accept-Language": "en,ja;q=0.8",
}
TIMEOUT = 30
KEEP_DAYS = 400
KEV_LIMIT = 30  # KEVカタログから取り込む最新件数

SOURCES = [
    {
        "id": "cisa",
        "name": "CISA(米国)",
        "country": "US",
        "theme": "cyber",
        "lang": "en",
        "site": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        # 上から順に試す。kev: で始まるものはJSON形式として扱う
        "feeds": [
            "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml",
            "kev:https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ],
    },
    {
        "id": "jpcert",
        "name": "JPCERT/CC(日本)",
        "country": "JP",
        "theme": "cyber",
        "lang": "ja",
        "site": "https://www.jpcert.or.jp/",
        "feeds": ["https://www.jpcert.or.jp/rss/jpcert.rdf"],
    },
    {
        "id": "ncsc",
        "name": "NCSC(英国)",
        "country": "GB",
        "theme": "cyber",
        "lang": "en",
        "site": "https://www.ncsc.gov.uk/",
        "feeds": [
            "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
            "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        ],
    },
]

EXCLUDE_KEYWORDS = [
    "russia", "russian", "kremlin", "moscow", "ukraine", "ukrainian",
    "fsb", "gru", "svr", "sanction", "sanctions",
    "ロシア", "ウクライナ", "クレムリン", "制裁",
]


def log(msg):
    print(msg, flush=True)


def strip_tags(text):
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def localname(tag):
    return tag.split("}")[-1] if "}" in tag else tag


def parse_date(value):
    if not value:
        return None
    value = value.strip()
    try:
        dt = parsedate_to_datetime(value)
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass
    iso = value.replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(iso, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def is_excluded(title):
    low = title.lower()
    return any(kw.lower() in low for kw in EXCLUDE_KEYWORDS)


def fetch(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
        return res.read()


def parse_feed(xml_bytes):
    """RSS 2.0 / RSS 1.0(RDF) / Atom を同じ形に揃える。"""
    root = ET.fromstring(xml_bytes)
    entries = []
    nodes = [el for el in root.iter() if localname(el.tag) in ("item", "entry")]

    for node in nodes:
        title = ""
        link = ""
        date = None
        for child in node:
            name = localname(child.tag)
            if name == "title" and not title:
                title = strip_tags(child.text)
            elif name == "link":
                href = child.attrib.get("href")
                rel = child.attrib.get("rel", "alternate")
                if href:
                    if rel == "alternate" and not link:
                        link = href.strip()
                elif child.text and not link:
                    link = child.text.strip()
            elif name in ("pubDate", "published", "updated", "date",
                          "modified", "created") and not date:
                date = parse_date(child.text)
            elif name == "guid" and not link and child.text:
                if child.text.startswith("http"):
                    link = child.text.strip()
        if title and link:
            entries.append({"title": title, "url": link, "published": date})
    return entries


def parse_kev(json_bytes):
    """CISAのKnown Exploited Vulnerabilities カタログ(JSON)を項目に変換する。"""
    data = json.loads(json_bytes.decode("utf-8"))
    vulns = data.get("vulnerabilities", [])

    def key(v):
        return v.get("dateAdded") or ""

    vulns = sorted(vulns, key=key, reverse=True)[:KEV_LIMIT]

    entries = []
    for v in vulns:
        cve = v.get("cveID", "")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        name = v.get("vulnerabilityName", "")
        if not cve:
            continue
        title = "KEV追加: %s %s — %s (%s)" % (vendor, product, name, cve)
        entries.append({
            "title": strip_tags(title),
            "url": "https://nvd.nist.gov/vuln/detail/" + cve,
            "published": parse_date(v.get("dateAdded")),
        })
    return entries


def collect_source(source):
    last_error = None
    for url in source["feeds"]:
        is_kev = url.startswith("kev:")
        real_url = url[4:] if is_kev else url
        try:
            raw = fetch(real_url)
            entries = parse_kev(raw) if is_kev else parse_feed(raw)
            if entries:
                log("  OK  %s: %d件 (%s)" % (source["id"], len(entries), real_url))
                return entries, real_url, None
            log("  空  %s: 0件 (%s)" % (source["id"], real_url))
            last_error = "0件"
        except Exception as e:
            log("  NG  %s: %s %s (%s)" % (source["id"], type(e).__name__, e, real_url))
            last_error = "%s: %s" % (type(e).__name__, e)
        time.sleep(2)
    return [], None, last_error or "取得できませんでした"


def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")


def main():
    now = datetime.now(timezone.utc)
    existing = load_json(ITEMS_PATH, {"items": []}).get("items", [])
    titles_ja = load_json(TITLES_JA_PATH, {})

    by_url = {it["url"]: it for it in existing}
    added = skipped = 0
    status = []

    log("収集開始 %s" % now.isoformat())
    for source in SOURCES:
        entries, used_feed, error = collect_source(source)
        status.append({
            "id": source["id"], "name": source["name"], "feed": used_feed,
            "count": len(entries), "error": error, "checked_at": now.isoformat(),
        })

        for e in entries:
            if is_excluded(e["title"]):
                skipped += 1
                continue
            if e["url"] in by_url:
                item = by_url[e["url"]]
                item["title"] = e["title"]
                # 後からフィードに日付が入った場合は正しい日付で上書きする
                if e["published"]:
                    item["published"] = e["published"]
                    item["date_estimated"] = False
                continue
            by_url[e["url"]] = {
                "title": e["title"],
                "url": e["url"],
                "published": e["published"] or now.isoformat(),
                # フィードに日付がなく、取得日で代用した場合に印を付ける
                "date_estimated": e["published"] is None,
                "first_seen": now.isoformat(),
                "source_id": source["id"],
                "source_name": source["name"],
                "country": source["country"],
                "theme": source["theme"],
                "lang": source["lang"],
            }
            added += 1

    for url, item in by_url.items():
        ja = titles_ja.get(url)
        if ja:
            item["title_ja"] = ja
        else:
            item.pop("title_ja", None)
        item.setdefault("date_estimated", False)

    items = list(by_url.values())

    def ts(it):
        try:
            return datetime.fromisoformat(it["published"]).timestamp()
        except Exception:
            return now.timestamp()

    cutoff = now.timestamp() - KEEP_DAYS * 86400
    items = [it for it in items if ts(it) >= cutoff]
    items.sort(key=ts, reverse=True)

    save_json(ITEMS_PATH, {
        "generated_at": now.isoformat(), "count": len(items), "items": items,
    })
    save_json(STATUS_PATH, {"generated_at": now.isoformat(), "sources": status})

    pending = {it["url"]: "" for it in items
               if it["lang"] != "ja" and not it.get("title_ja")}
    save_json(os.path.join(DATA_DIR, "titles_ja_pending.json"), pending)

    log("完了: 新規%d件 / 除外%d件 / 合計%d件" % (added, skipped, len(items)))
    log("未翻訳の見出し: %d件" % len(pending))

    if all(s["count"] == 0 for s in status):
        log("すべての情報源から取得できませんでした")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
