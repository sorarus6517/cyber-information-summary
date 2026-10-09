#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
規制・当局アップデート横断ビューア — 収集スクリプト(v0.3)

v0.2からの変更点
・情報源に JVN と IPA を追加
・CISAのKEVは見出しを自動で日本語化(脆弱性の種類を対訳表で変換)
・手動の対訳(titles_ja.json)がある場合はそちらを優先
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

CONTACT = "https://cyber-information-summary.pages.dev"
USER_AGENT = ("Mozilla/5.0 (compatible; RegWatchBot/0.3; +%s) "
              "personal non-commercial aggregator" % CONTACT)
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/rss+xml, application/atom+xml, application/xml, "
              "text/xml, application/json;q=0.9, */*;q=0.8",
    "Accept-Language": "ja,en;q=0.8",
}
TIMEOUT = 30
KEEP_DAYS = 400
KEV_LIMIT = 30

SOURCES = [
    {"id": "cisa", "name": "CISA(米国)", "country": "US", "theme": "cyber",
     "lang": "en", "site": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
     "feeds": [
         "https://www.cisa.gov/cybersecurity-advisories/all.xml",
         "kev:https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     ]},
    {"id": "jpcert", "name": "JPCERT/CC(日本)", "country": "JP", "theme": "cyber",
     "lang": "ja", "site": "https://www.jpcert.or.jp/",
     "feeds": ["https://www.jpcert.or.jp/rss/jpcert.rdf"]},
    {"id": "ncsc", "name": "NCSC(英国)", "country": "GB", "theme": "cyber",
     "lang": "en", "site": "https://www.ncsc.gov.uk/",
     "feeds": ["https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"]},
    {"id": "jvn", "name": "JVN(日本)", "country": "JP", "theme": "cyber",
     "lang": "ja", "site": "https://jvn.jp/",
     "feeds": ["https://jvn.jp/rss/jvn.rdf"]},
    {"id": "ipa", "name": "IPA(日本)", "country": "JP", "theme": "cyber",
     "lang": "ja", "site": "https://www.ipa.go.jp/security/",
     "feeds": ["https://www.ipa.go.jp/security/alert-rss.rdf",
               "https://www.ipa.go.jp/security/rss/alert.rdf"]},
]

EXCLUDE_KEYWORDS = [
    "russia", "russian", "kremlin", "moscow", "ukraine", "ukrainian",
    "fsb", "gru", "svr", "sanction", "sanctions",
    "ロシア", "ウクライナ", "クレムリン", "制裁",
]

# 脆弱性の種類の対訳(長い語句から順に照合する)
VULN_TYPES = {
    "improper restriction of operations within the bounds of a memory buffer":
        "メモリ範囲外の操作(バッファ処理の不備)",
    "improper check for unusual or exceptional conditions": "例外条件のチェック不備",
    "unrestricted upload of file with dangerous type": "危険な種類のファイルのアップロード制限不備",
    "exposure of dangerous method or function": "危険なメソッド・機能の公開",
    "cleartext storage of sensitive information": "重要情報の平文保存",
    "exposure of sensitive information": "重要情報の漏えい",
    "missing authentication for critical function": "重要機能における認証の欠如",
    "improper enforcement of behavioral workflow": "処理手順の制御不備",
    "deserialization of untrusted data": "信頼できないデータのデシリアライズ",
    "incorrect use of privileged apis": "特権APIの不適切な利用",
    "server-side request forgery": "サーバーサイドリクエストフォージェリ(SSRF)",
    "cross-site request forgery": "クロスサイトリクエストフォージェリ(CSRF)",
    "improper certificate validation": "証明書検証の不備",
    "incorrect default permissions": "既定の権限設定の不備",
    "use of hard-coded credentials": "ハードコードされた認証情報",
    "remote file inclusion": "リモートファイルインクルージョン",
    "improper privilege management": "権限管理の不備",
    "stack-based buffer overflow": "スタックバッファオーバーフロー",
    "heap-based buffer overflow": "ヒープバッファオーバーフロー",
    "improper input validation": "入力値検証の不備",
    "cross-site scripting": "クロスサイトスクリプティング(XSS)",
    "improper access control": "アクセス制御の不備",
    "incorrect authorization": "認可の不備",
    "improper authorization": "認可の不備",
    "improper authentication": "認証の不備",
    "authentication bypass": "認証回避",
    "data processing errors": "データ処理の誤り",
    "os command injection": "OSコマンドインジェクション",
    "command injection": "コマンドインジェクション",
    "code injection": "コードインジェクション",
    "sql injection": "SQLインジェクション",
    "path traversal": "パストラバーサル",
    "out-of-bounds write": "境界外書き込み",
    "out-of-bounds read": "境界外読み取り",
    "buffer overflow": "バッファオーバーフロー",
    "use-after-free": "解放済みメモリの使用",
    "race condition": "競合状態",
    "session fixation": "セッション固定",
    "privilege escalation": "権限昇格",
    "information disclosure": "情報漏えい",
}


def log(msg):
    print(msg, flush=True)


def strip_tags(text):
    if not text:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", text)).strip()


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
                "%Y-%m-%dT%H:%M%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
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
    root = ET.fromstring(xml_bytes)
    entries = []
    for node in [el for el in root.iter() if localname(el.tag) in ("item", "entry")]:
        title = link = ""
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
                          "issued", "modified", "created") and not date:
                date = parse_date(child.text)
            elif name == "guid" and not link and child.text:
                if child.text.startswith("http"):
                    link = child.text.strip()
        if title and link:
            entries.append({"title": title, "url": link, "published": date,
                            "title_ja": None})
    return entries


def ja_vuln_type(text):
    """英語の脆弱性名から種類を取り出して日本語にする。対訳がなければ原文を返す。"""
    cleaned = re.sub(r"\s+vulnerabilit(y|ies)$", "", text.strip(), flags=re.I).strip()
    low = cleaned.lower()
    for en in sorted(VULN_TYPES, key=len, reverse=True):
        if en in low:
            return VULN_TYPES[en]
    return cleaned or text.strip()


def parse_kev(json_bytes):
    data = json.loads(json_bytes.decode("utf-8"))
    vulns = sorted(data.get("vulnerabilities", []),
                   key=lambda v: v.get("dateAdded") or "", reverse=True)[:KEV_LIMIT]
    entries = []
    for v in vulns:
        cve = v.get("cveID", "")
        if not cve:
            continue
        vendor = (v.get("vendorProject") or "").strip()
        product = (v.get("product") or "").strip()
        name = (v.get("vulnerabilityName") or "").strip()
        target = (vendor + " " + product).strip()

        # 「ベンダー名 製品名」が脆弱性名の先頭に重複して入っているので取り除く
        kind = name
        for prefix in (target, vendor, product):
            if prefix and kind.lower().startswith(prefix.lower()):
                kind = kind[len(prefix):].strip()
        kind_ja = ja_vuln_type(kind or name)

        entries.append({
            "title": "KEV追加: %s — %s (%s)" % (target, name, cve),
            "title_ja": "悪用確認(KEV): %s — %s (%s)" % (target, kind_ja, cve),
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
        status.append({"id": source["id"], "name": source["name"], "feed": used_feed,
                       "count": len(entries), "error": error,
                       "checked_at": now.isoformat()})

        for e in entries:
            if is_excluded(e["title"]):
                skipped += 1
                continue
            if e["url"] in by_url:
                item = by_url[e["url"]]
                item["title"] = e["title"]
                if e.get("title_ja"):
                    item["title_ja"] = e["title_ja"]
                    item["title_ja_source"] = "auto"
                if e["published"]:
                    item["published"] = e["published"]
                    item["date_estimated"] = False
                continue
            item = {
                "title": e["title"],
                "url": e["url"],
                "published": e["published"] or now.isoformat(),
                "date_estimated": e["published"] is None,
                "first_seen": now.isoformat(),
                "source_id": source["id"],
                "source_name": source["name"],
                "country": source["country"],
                "theme": source["theme"],
                "lang": source["lang"],
            }
            if e.get("title_ja"):
                item["title_ja"] = e["title_ja"]
                item["title_ja_source"] = "auto"
            by_url[e["url"]] = item
            added += 1

    # 手動の対訳が最優先。なければ自動生成のものを残す。
    for url, item in by_url.items():
        manual = titles_ja.get(url)
        if manual:
            item["title_ja"] = manual
            item["title_ja_source"] = "manual"
        elif item.get("title_ja_source") != "auto":
            item.pop("title_ja", None)
            item.pop("title_ja_source", None)
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

    save_json(ITEMS_PATH, {"generated_at": now.isoformat(),
                           "count": len(items), "items": items})
    save_json(STATUS_PATH, {"generated_at": now.isoformat(), "sources": status})

    # 日本語の見出しがまだ無いものだけを書き出す(手動で訳す用)
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
