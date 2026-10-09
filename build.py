#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ページ生成スクリプト(v0.3)

data/items.json をもとに、検索エンジンに載るページと配信用のファイルを作る。

生成されるもの
・w/YYYY-Www.html   週ごとのまとめページ(本文があるので検索に載りやすい)
・archive.html      週ごとのまとめの一覧
・feed.xml          このサイト自身のRSS(読者が購読できる)
・sitemap.xml       検索エンジン向けの地図
・robots.txt        検索エンジン向けの案内
"""

import html
import json
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
ITEMS_PATH = os.path.join(DATA_DIR, "items.json")
WEEK_DIR = os.path.join(ROOT, "w")

SITE_URL = "https://cyber-information-summary.pages.dev"
SITE_NAME = "公式セキュリティ情報まとめ"
VERIFY_META = ('<meta name="google-site-verification" content="-yUwQXTz4etJef7kX5fnyTQXLTrKwNhpkPILpJBuGrM" />')

SITE_DESC = ("米国CISA・日本JPCERT/CC・JVN・IPA・英国NCSCが公表した"
             "サイバーセキュリティの注意喚起を、日本語で横断的にまとめています。")
FEED_ITEMS = 50
WEEKS_ON_SITEMAP = 60

# ----- お知らせメールの設定 -----------------------------------------------
# 登録フォームのURL(GoogleフォームやTallyで作って貼る)。空なら「準備中」と表示。
SIGNUP_FORM_URL = ""
# 公開してよい問い合わせ先。空なら表示しない。
CONTACT_EMAIL = ""
# 週1回のメール本文の下書きを data/digest-latest.md に生成する
DIGEST_MAX = 40

# ----- Xの投稿下書きの設定 -------------------------------------------------
# data/x-draft.md に、そのままコピーできる投稿文を作る。
X_LIMIT = 280          # Xの1投稿の上限(日本語1文字=2、URL=23として数える)
X_HASHTAGS = "#セキュリティ #脆弱性情報"
X_HIGHLIGHTS = 2       # 週まとめに載せる「注目」の件数
X_ITEM_DRAFTS = 12     # 1件ずつ紹介する下書きを作る件数

CSS = """
:root{--bg:#f7f8fa;--panel:#fff;--text:#15181d;--muted:#5c6572;--line:#e2e5ea;--accent:#1f5fd0}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--panel:#1c2026;--text:#e9ecf1;--muted:#9aa4b2;--line:#2b313a;--accent:#6f9df5}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);line-height:1.8;font-size:15px;
font-family:-apple-system,BlinkMacSystemFont,"Hiragino Sans","Noto Sans JP","Yu Gothic",Meiryo,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:24px 16px 64px}
a{color:var(--accent)}
h1{font-size:21px;line-height:1.5;margin:0 0 6px}
h2{font-size:17px;margin:28px 0 8px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.lead{color:var(--muted);font-size:14px;margin:0 0 20px}
nav.top{font-size:13px;margin-bottom:18px}
nav.top a{margin-right:14px}
ul.items{list-style:none;margin:0;padding:0}
ul.items li{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:12px 14px;margin-bottom:10px}
.t{font-weight:600;margin:0 0 2px}
.t a{color:inherit;text-decoration:none}
.t a:hover{color:var(--accent);text-decoration:underline}
.orig,.date{color:var(--muted);font-size:12.5px;margin:0}
footer{border-top:1px solid var(--line);margin-top:36px;padding-top:14px;
color:var(--muted);font-size:12.5px}
"""

SOURCE_ORDER = ["jpcert", "jvn", "ipa", "cisa", "ncsc"]


def esc(s):
    return html.escape(s or "", quote=True)


def load_items():
    with open(ITEMS_PATH, encoding="utf-8") as f:
        return json.load(f)


def to_dt(iso):
    try:
        dt = datetime.fromisoformat(iso)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def jp_date(dt):
    return "%d年%d月%d日" % (dt.year, dt.month, dt.day)


def week_key(dt):
    y, w, _ = dt.isocalendar()
    return "%04d-W%02d" % (y, w)


def week_range(key):
    y, w = int(key[:4]), int(key[6:])
    monday = datetime.fromisocalendar(y, w, 1).replace(tzinfo=timezone.utc)
    return monday, monday + timedelta(days=6)


def page(title, description, canonical, body, extra_head=""):
    return """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
%s
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<meta name="description" content="%s">
<link rel="canonical" href="%s">
<link rel="alternate" type="application/rss+xml" title="%s" href="%s/feed.xml">
%s<style>%s</style>
</head>
<body><div class="wrap">
<nav class="top"><a href="/">最新一覧</a><a href="/archive.html">週ごとのまとめ</a><a href="/feed.xml">RSS</a></nav>
%s
<footer>
<p>本サイトは各国の公的機関が公表した情報の所在を案内するものです。公式機関とは関係がありません。内容は必ず原文をご確認ください。</p>
<p>英語の発表には日本語の見出しを添えています。機械的に変換した部分を含むため、正確な内容は原文でご確認ください。</p>
</footer>
</div></body>
</html>
""" % (VERIFY_META, esc(title), esc(description), esc(canonical), esc(SITE_NAME),
       SITE_URL, extra_head, CSS, body)


def render_items(items):
    out = ["<ul class=\"items\">"]
    for it in items:
        dt = to_dt(it["published"])
        label = ("確認日 " if it.get("date_estimated") else "") + (jp_date(dt) if dt else "")
        ja = it.get("title_ja")
        shown = ja or it["title"]
        out.append("<li>")
        out.append('<p class="t"><a href="%s" target="_blank" rel="noopener noreferrer nofollow">%s</a></p>'
                   % (esc(it["url"]), esc(shown)))
        if ja and ja != it["title"]:
            out.append('<p class="orig">%s</p>' % esc(it["title"]))
        out.append('<p class="date">%s ・ %s</p>' % (esc(it["source_name"]), esc(label)))
        out.append("</li>")
    out.append("</ul>")
    return "\n".join(out)


def build_week_pages(items):
    weeks = OrderedDict()
    for it in items:
        dt = to_dt(it["published"])
        if not dt:
            continue
        weeks.setdefault(week_key(dt), []).append(it)

    os.makedirs(WEEK_DIR, exist_ok=True)
    built = []
    for key, rows in sorted(weeks.items(), reverse=True):
        start, end = week_range(key)
        title = "%s〜%s のサイバー注意喚起まとめ｜%s" % (jp_date(start), jp_date(end), SITE_NAME)

        by_src = OrderedDict()
        for it in rows:
            by_src.setdefault(it["source_id"], []).append(it)
        names = [by_src[s][0]["source_name"] for s in SOURCE_ORDER if s in by_src]
        desc = "%s〜%sに%sが公表したサイバーセキュリティの注意喚起・脆弱性情報%d件を、日本語の見出しでまとめています。" % (
            jp_date(start), jp_date(end), "、".join(names) or "各機関", len(rows))

        body = ['<h1>%s〜%s のサイバー注意喚起まとめ</h1>' % (jp_date(start), jp_date(end))]
        body.append('<p class="lead">%s</p>' % esc(desc))
        for sid in SOURCE_ORDER:
            if sid not in by_src:
                continue
            rows_s = sorted(by_src[sid], key=lambda x: x["published"], reverse=True)
            body.append("<h2>%s（%d件）</h2>" % (esc(rows_s[0]["source_name"]), len(rows_s)))
            body.append(render_items(rows_s))

        canonical = "%s/w/%s.html" % (SITE_URL, key)
        with open(os.path.join(WEEK_DIR, key + ".html"), "w", encoding="utf-8") as f:
            f.write(page(title, desc, canonical, "\n".join(body)))
        built.append((key, start, end, len(rows)))
    return built


def build_archive(built):
    body = ["<h1>週ごとのまとめ</h1>",
            '<p class="lead">各週に公表された注意喚起を、機関ごとに整理しています。</p>',
            '<ul class="items">']
    for key, start, end, n in built:
        body.append('<li><p class="t"><a href="/w/%s.html">%s〜%s のまとめ</a></p>'
                    '<p class="date">%d件</p></li>' % (key, jp_date(start), jp_date(end), n))
    body.append("</ul>")
    with open(os.path.join(ROOT, "archive.html"), "w", encoding="utf-8") as f:
        f.write(page("週ごとのまとめ｜" + SITE_NAME,
                     "各国の公的機関が公表したサイバーセキュリティ注意喚起を、週ごとに日本語でまとめた一覧です。",
                     SITE_URL + "/archive.html", "\n".join(body)))


def build_notify():
    """お知らせメールの案内ページ。登録フォームのURLが未設定なら準備中と表示する。"""
    body = ["<h1>更新のお知らせを受け取る</h1>",
            '<p class="lead">新しい注意喚起が出たときに気づけるよう、2つの方法を用意しています。'
            'いずれも無料です。</p>',
            "<h2>1. RSSで受け取る(すぐ使えます)</h2>",
            "<p>RSSリーダーに <a href=\"/feed.xml\">%s/feed.xml</a> を登録してください。"
            "新しい項目が自動で届きます。メールで受け取りたい場合は、InoreaderやBlogtrottrなどの"
            "無料サービスにこのRSSを登録すると、メールに転送できます。"
            "この方法なら、本サイトがあなたのメールアドレスを預かることはありません。</p>" % SITE_URL,
            "<h2>2. 週1回のお知らせメール</h2>"]

    if SIGNUP_FORM_URL:
        body.append('<p>下のフォームからご登録いただくと、その週に公表された注意喚起を'
                    'まとめて週1回お送りします。</p>')
        body.append('<p><a href="%s">お知らせメールに登録する</a></p>' % esc(SIGNUP_FORM_URL))
        body.append("<h2>お預かりする情報について</h2>")
        body.append("<p>登録いただいたメールアドレスは、お知らせメールの配信のためだけに利用し、"
                    "第三者に提供しません。配信停止は、メール内のリンクまたは下記の連絡先への"
                    "ご連絡でいつでも行えます。</p>")
    else:
        body.append('<p>現在準備中です。公開まではRSSをご利用ください。</p>')

    if CONTACT_EMAIL:
        body.append("<h2>連絡先</h2><p>%s</p>" % esc(CONTACT_EMAIL))

    body.append("<h2>将来の予定</h2>")
    body.append("<p>製品名や機関で絞り込んだ通知、公表当日に届く通知、チームでの共有は、"
                "有料の機能として準備中です。</p>")

    with open(os.path.join(ROOT, "notify.html"), "w", encoding="utf-8") as f:
        f.write(page("更新のお知らせを受け取る｜" + SITE_NAME,
                     "各国の公的機関が公表したサイバーセキュリティ注意喚起の更新を、"
                     "RSSまたは週1回のメールで受け取る方法の案内です。",
                     SITE_URL + "/notify.html", "\n".join(body)))


def build_digest(items):
    """週1回のお知らせメールの本文の下書きを作る(そのままコピーして送れる形)。"""
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    rows = []
    for it in items:
        dt = to_dt(it["published"])
        if dt and dt >= week_ago:
            rows.append((dt, it))
    rows.sort(key=lambda x: x[0], reverse=True)
    rows = rows[:DIGEST_MAX]

    lines = ["件名: 今週のサイバー注意喚起まとめ(%s時点 / %d件)" % (jp_date(now), len(rows)),
             "",
             "%s です。直近1週間に各国の公的機関が公表した注意喚起をまとめました。" % SITE_NAME,
             ""]
    by_src = OrderedDict()
    for dt, it in rows:
        by_src.setdefault(it["source_id"], []).append((dt, it))
    for sid in SOURCE_ORDER:
        if sid not in by_src:
            continue
        lines.append("■ %s" % by_src[sid][0][1]["source_name"])
        for dt, it in by_src[sid]:
            lines.append("・%s（%s）" % (it.get("title_ja") or it["title"], jp_date(dt)))
            lines.append("  %s" % it["url"])
        lines.append("")
    lines.append("すべての項目: %s/" % SITE_URL)
    lines.append("週ごとのまとめ: %s/archive.html" % SITE_URL)
    lines.append("")
    lines.append("配信停止をご希望の場合は、このメールにご返信ください。")

    with open(os.path.join(DATA_DIR, "digest-latest.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return len(rows)


def x_len(text):
    """Xの数え方で文字数を数える。URLは一律23文字、日本語などは2文字、半角は1文字。"""
    t = re.sub(r"https?://\S+", "u" * 23, text)
    n = 0
    for ch in t:
        c = ord(ch)
        if c <= 4351 or 8192 <= c <= 8205 or 8208 <= c <= 8223 or 8242 <= c <= 8247:
            n += 1
        else:
            n += 2
    return n


def x_trim(text, limit):
    """Xの数え方で limit に収まるまで末尾を削り、削ったときは … を付ける。"""
    t = " ".join((text or "").split())
    if x_len(t) <= limit:
        return t
    while t and x_len(t + "…") > limit:
        t = t[:-1]
    return t + "…" if t else ""


def build_x_draft(items, built):
    """Xにそのまま貼れる投稿文の下書きを data/x-draft.md に作る。"""
    now = datetime.now(timezone.utc)
    key = built[0][0] if built else week_key(now)
    start, end = week_range(key)
    week_url = "%s/w/%s.html" % (SITE_URL, key)

    rows = []
    for it in items:
        dt = to_dt(it["published"])
        if dt and start <= dt <= end + timedelta(days=1):
            rows.append((dt, it))
    rows.sort(key=lambda x: x[0], reverse=True)

    by_src = OrderedDict()
    for dt, it in rows:
        by_src.setdefault(it["source_id"], []).append((dt, it))
    counts = []
    for sid in SOURCE_ORDER:
        if sid in by_src:
            name = by_src[sid][0][1]["source_name"].split("(")[0]
            counts.append("%s %d" % (name, len(by_src[sid])))

    period = "%d月%d日〜%d月%d日" % (start.month, start.day, end.month, end.day)
    head = ["【今週の公式セキュリティ情報】" + period,
            "・".join(counts) + "（計%d件）" % len(rows)]
    tail = ["一覧はこちら", week_url, X_HASHTAGS]

    def compose(picks):
        middle = ["", "注目:"] + picks if picks else []
        return "\n".join(head + middle + [""] + tail)

    # 悪用が確認された脆弱性(KEV)、次にJPCERT/CCの注意喚起を優先して「注目」に出す
    def priority(pair):
        dt, it = pair
        ja = it.get("title_ja") or it["title"]
        if "悪用確認" in ja:
            rank = 0
        elif it["source_id"] == "jpcert" and "注意喚起" in ja:
            rank = 1
        else:
            rank = 2
        return (rank, -dt.timestamp())

    # 上限に収まるぶんだけ「注目」を足す(長い見出しは末尾を詰める)
    picks = []
    for dt, it in sorted(rows, key=priority):
        if len(picks) >= X_HIGHLIGHTS:
            break
        ja = it.get("title_ja") or it["title"]
        cand = picks + ["・" + ja]
        over = x_len(compose(cand)) - X_LIMIT
        if over > 0:
            allowed = x_len(ja) - over
            if allowed < 24:
                break
            cand = picks + ["・" + x_trim(ja, allowed)]
            if x_len(compose(cand)) > X_LIMIT:
                break
        picks = cand

    weekly = compose(picks)

    out = ["# Xの投稿下書き（%s 自動生成）" % jp_date(now),
           "",
           "そのままコピーして投稿できます。[ ]内はXの数え方での文字数（上限%d）です。"
           % X_LIMIT,
           "日本語1文字=2、URL=23として数えています。",
           "",
           "---",
           "",
           "## 1. 今週のまとめ（1投稿） [ %d / %d ]" % (x_len(weekly), X_LIMIT),
           "",
           "```",
           weekly,
           "```",
           ""]

    if rows:
        out += ["---", "",
                "## 2. 1件ずつ紹介する下書き（新しい順に最大%d件）" % X_ITEM_DRAFTS,
                ""]
        for dt, it in rows[:X_ITEM_DRAFTS]:
            name = it["source_name"].split("(")[0]
            fixed = "【%s】\n%s\n#セキュリティ" % (name, it["url"])
            room2 = X_LIMIT - x_len(fixed)
            title = x_trim(it.get("title_ja") or it["title"], room2)
            body = "【%s】%s\n%s\n#セキュリティ" % (name, title, it["url"])
            out += ["### %s（%s） [ %d / %d ]"
                    % (name, jp_date(dt), x_len(body), X_LIMIT),
                    "", "```", body, "```", ""]
    else:
        out += ["（この週はまだ新着がありません）", ""]

    with open(os.path.join(DATA_DIR, "x-draft.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    return len(rows)


def rfc822(dt):
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return "%s, %02d %s %04d %02d:%02d:%02d +0000" % (
        days[dt.weekday()], dt.day, months[dt.month - 1], dt.year,
        dt.hour, dt.minute, dt.second)


def build_feed(items):
    now = datetime.now(timezone.utc)
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<rss version="2.0"><channel>',
           "<title>%s</title>" % esc(SITE_NAME),
           "<link>%s/</link>" % SITE_URL,
           "<description>%s</description>" % esc(SITE_DESC),
           "<language>ja</language>",
           "<lastBuildDate>%s</lastBuildDate>" % rfc822(now)]
    for it in items[:FEED_ITEMS]:
        dt = to_dt(it["published"]) or now
        shown = it.get("title_ja") or it["title"]
        out.append("<item>")
        out.append("<title>%s</title>" % esc("[%s] %s" % (it["source_name"], shown)))
        out.append("<link>%s</link>" % esc(it["url"]))
        out.append('<guid isPermaLink="true">%s</guid>' % esc(it["url"]))
        out.append("<pubDate>%s</pubDate>" % rfc822(dt))
        out.append("<description>%s</description>"
                   % esc("%s が公表。原文: %s" % (it["source_name"], it["url"])))
        out.append("</item>")
    out.append("</channel></rss>")
    with open(os.path.join(ROOT, "feed.xml"), "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def build_sitemap(built):
    urls = [SITE_URL + "/", SITE_URL + "/archive.html", SITE_URL + "/notify.html"]
    urls += ["%s/w/%s.html" % (SITE_URL, k) for k, _, _, _ in built[:WEEKS_ON_SITEMAP]]
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for u in urls:
        out.append("<url><loc>%s</loc><lastmod>%s</lastmod></url>" % (esc(u), today))
    out.append("</urlset>")
    with open(os.path.join(ROOT, "sitemap.xml"), "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

    with open(os.path.join(ROOT, "robots.txt"), "w", encoding="utf-8") as f:
        f.write("User-agent: *\nAllow: /\nSitemap: %s/sitemap.xml\n" % SITE_URL)


def main():
    data = load_items()
    items = data.get("items", [])
    if not items:
        print("items.json が空です")
        return 1
    built = build_week_pages(items)
    build_archive(built)
    build_notify()
    build_feed(items)
    build_sitemap(built)
    n = build_digest(items)
    x = build_x_draft(items, built)
    print("生成: 週ページ%d件 / archive.html / notify.html / feed.xml / sitemap.xml / "
          "robots.txt / digest-latest.md(%d件) / x-draft.md(今週%d件)"
          % (len(built), n, x))
    return 0


if __name__ == "__main__":
    sys.exit(main())
