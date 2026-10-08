#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
規制・当局アップデート横断ビューア — 収集スクリプト

各機関の公式フィード(RSS/Atom/RDF)を取得し、
data/items.json に正規化して追記する。

・標準ライブラリのみで動作(追加インストール不要)
・既存の items.json と突き合わせて重複を除外し、履歴を残す
・本文は保存せず、見出し・日付・出典・原文URLのみを持つ
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

USER_AGENT = (
    "RegWatchBot/0.1 (+https://example.com; personal non-commercial aggregator; "
    "contact: your-mail@example.com)"
)
TIMEOUT = 30
KEEP_DAYS = 400  # これより古い項目は items.json から落とす

# --- 情報源の定義 -----------------------------------------------------------
# feeds は候補を上から順に試し、最初に成功したものを使う。
SOURCES = [
    {
        "id": "cisa",
        "name": "CISA(米国)",
        "full_name": "Cybersecurity and Infrastructure Security Agency",
        "country": "US",
        "theme": "cyber",
        "lang": "en",
        "site": "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "feeds": [
            "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "https://www.cisa.gov/news.xml",
        ],
    },
    {
        "id": "jpcert",
        "name": "JPCERT/CC(日本)",
        "full_name": "JPCERT コーディネーションセンター",
        "country": "JP",
        "theme": "cyber",
        "lang": "ja",
        "site": "https://www.jpcert.or.jp/",
        "feeds": [
            "https://www.jpcert.or.jp/rss/jpcert.rdf",
        ],
    },
    {
        "id": "ncsc",
        "name": "NCSC(英国)",
        "full_name": "National Cyber Security Centre",
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

# ロシア関連の話題を除外するためのキーワード(見出しに含まれていたら取り込まない)
EXCLUDE_KEYWORDS = [
    "russia", "russian", "kremlin", "moscow", "ukraine", "ukrainian",
    "fsb", "gru", "svr", "sanction", "sanctions",
    "ロシア", "ウクライナ", "クレムリン", "制裁",
]


# --- ユーティリティ ---------------------------------------------------------
def log(msg):
    print(msg, flush=True)


def strip_tags(text):
    """見出しに混ざるHTMLタグや余分な空白を落とす。"""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def localname(tag):
    """{名前空間}タグ名 → タグ名"""
    return tag.split("}")[-1] if "}" in tag else tag


def parse_date(value):
    """RSS/Atom のいろいろな日付表記を ISO 8601(UTC)に揃える。"""
    if not value:
        return None
    value = value.strip()
    # RFC 822 (RSS 2.0)
    try:
        dt = parsedate_to_datetime(value)
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass
    # ISO 8601 (Atom / Dublin Core)
    iso = value.replace("Z", "+00:00")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
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
    for kw in EXCLUDE_KEYWORDS:
        if kw.lower() in low:
            return True
    return False


# --- フィードの取得と解析 ---------------------------------------------------
def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
        return res.read()


def parse_feed(xml_bytes):
    """RSS 2.0 / RSS 1.0(RDF) / Atom を同じ形に揃えて返す。"""
    root = ET.fromstring(xml_bytes)
    entries = []

    # 項目に相当する要素を集める(item / entry)
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
                # Atom は href 属性、RSS はテキスト
                href = child.attrib.get("href")
                rel = child.attrib.get("rel", "alternate")
                if href:
                    if rel == "alternate" and not link:
                        link = href.strip()
                elif child.text and not link:
                    link = child.text.strip()
            elif name in ("pubDate", "published", "updated", "date") and not date:
                date = parse_date(child.text)
            elif name == "guid" and not link and child.text:
                if child.text.startswith("http"):
                    link = child.text.strip()

        if title and link:
            entries.append({"title": title, "url": link, "published": date})

    return entries


def collect_source(source):
    """1つの情報源について、候補フィードを順に試す。"""
    for url in source["feeds"]:
        try:
            raw = fetch(url)
            entries = parse_feed(raw)
            if entries:
                log(f"  OK  {source['id']}: {len(entries)}件 ({url})")
                return entries, url, None
            log(f"  空  {source['id']}: 0件 ({url})")
        except (urllib.error.URLError, urllib.error.HTTPError, ET.ParseError) as e:
            log(f"  NG  {source['id']}: {type(e).__name__} ({url})")
            last_error = f"{type(e).__name__}: {e}"
            continue
        except Exception as e:  # 想定外でも全体を止めない
            log(f"  NG  {source['id']}: {type(e).__name__} ({url})")
            last_error = f"{type(e).__name__}: {e}"
            continue
        time.sleep(1)
    return [], None, "すべての候補フィードで取得できませんでした"


# --- 保存 -------------------------------------------------------------------
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
    added = 0
    skipped = 0
    status = []

    log(f"収集開始 {now.isoformat()}")
    for source in SOURCES:
        entries, used_feed, error = collect_source(source)
        status.append({
            "id": source["id"],
            "name": source["name"],
            "feed": used_feed,
            "count": len(entries),
            "error": error,
            "checked_at": now.isoformat(),
        })

        for e in entries:
            if is_excluded(e["title"]):
                skipped += 1
                continue
            if e["url"] in by_url:
                # 既にあるものは日付と見出しだけ更新しておく
                by_url[e["url"]]["title"] = e["title"]
                if e["published"]:
                    by_url[e["url"]]["published"] = e["published"]
                continue
            by_url[e["url"]] = {
                "title": e["title"],
                "url": e["url"],
                "published": e["published"] or now.isoformat(),
                "first_seen": now.isoformat(),
                "source_id": source["id"],
                "source_name": source["name"],
                "country": source["country"],
                "theme": source["theme"],
                "lang": source["lang"],
            }
            added += 1

    # 日本語見出し(あれば)を反映
    for url, item in by_url.items():
        ja = titles_ja.get(url)
        if ja:
            item["title_ja"] = ja
        elif "title_ja" in item and not ja:
            item.pop("title_ja", None)

    items = list(by_url.values())

    # 古すぎるものを落とす
    cutoff = now.timestamp() - KEEP_DAYS * 86400
    def ts(it):
        try:
            return datetime.fromisoformat(it["published"]).timestamp()
        except Exception:
            return now.timestamp()
    items = [it for it in items if ts(it) >= cutoff]
    items.sort(key=ts, reverse=True)

    save_json(ITEMS_PATH, {
        "generated_at": now.isoformat(),
        "count": len(items),
        "items": items,
    })
    save_json(STATUS_PATH, {"generated_at": now.isoformat(), "sources": status})

    # 日本語見出しの雛形を更新(未翻訳のものを書き出す)
    pending = {
        it["url"]: ""
        for it in items
        if it["lang"] != "ja" and not it.get("title_ja")
    }
    save_json(os.path.join(DATA_DIR, "titles_ja_pending.json"), pending)

    log(f"完了: 新規{added}件 / 除外{skipped}件 / 合計{len(items)}件")
    log(f"未翻訳の見出し: {len(pending)}件")

    # すべての情報源が失敗したら異常終了(Actions で気づけるように)
    if all(s["count"] == 0 for s in status):
        log("すべての情報源から取得できませんでした")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
