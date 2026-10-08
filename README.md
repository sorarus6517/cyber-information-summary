# サイバー勧告ウォッチ(仮) — セットアップ手順

米国 CISA・日本 JPCERT/CC・英国 NCSC の公式な注意喚起を、1日1回自動で集めて
日本語の一覧として公開するための最小構成です。サーバーは不要で、費用は0円から始められます。

## 構成

```
regwatch/
├── collect.py                     情報を集めて data/ を更新するスクリプト(標準ライブラリのみ)
├── index.html                     表示用のページ(1ファイル完結・外部ライブラリなし)
├── data/
│   ├── items.json                 集めた項目(自動更新)
│   ├── status.json                各情報源の取得状況(自動更新)
│   ├── titles_ja.json             英語の見出しに付ける日本語訳(手動)
│   └── titles_ja_pending.json     未翻訳のURL一覧(自動生成)
└── .github/workflows/collect.yml  1日1回の自動実行設定
```

動き方はこうです。

1. GitHub Actions が毎日1回 `collect.py` を実行する(あなたのパソコンは不要)
2. 各機関の公式フィードから「見出し・日付・原文URL」だけを取得する
3. 結果を `data/items.json` に書き出し、自動でコミットする
4. コミットを検知して Cloudflare Pages がサイトを更新する
5. 訪問者はブラウザで `data/items.json` を読み込んだページを見る

本文は保存しません。各項目は公式サイトの原文へリンクします。

## 初回のセットアップ

### 1. GitHub にリポジトリを作る

1. GitHub で新しいリポジトリを作る(公開・非公開どちらでも可。非公開でも Actions は月2,000分まで無料)
2. このフォルダの中身をそのままアップロードする(`.github` フォルダを忘れずに)

### 2. Actions に書き込み権限を与える

リポジトリの Settings → Actions → General → Workflow permissions で
**「Read and write permissions」** を選んで保存します。これがないと自動コミットが失敗します。

### 3. 手動で1回実行して動作を確認する

Actions タブ → 左の「collect」→ 「Run workflow」。
緑のチェックが付き、`data/items.json` に項目が入れば成功です。

うまくいかない場合は、実行ログの `OK` / `NG` の行を見てください。
`NG` が出た情報源は、`collect.py` の `SOURCES` にある `feeds` のURLを見直します
(各機関がフィードのURLを変更することがあります)。

### 4. Cloudflare Pages につなぐ

1. Cloudflare に無料で登録する(クレジットカード不要)
2. Workers & Pages → Create → Pages → 「Connect to Git」でリポジトリを選ぶ
3. ビルド設定は次のようにする
   - Framework preset: **None**
   - Build command: **空欄**
   - Build output directory: **/**(ルート)
4. デプロイすると `https://好きな名前.pages.dev` で公開されます

以降は、GitHub にコミットが入るたびに自動で更新されます。

### 5. (任意)独自ドメインを付ける

Cloudflare Pages の Custom domains から設定します。
ドメインは Cloudflare Registrar で年$10程度、または GitHub Student Developer Pack の
学生特典(Namecheap の .me が1年無料)でも取得できます。

## 日常の運用

### 英語の見出しに日本語を付ける

1. `data/titles_ja_pending.json` を開く(未翻訳のURLが並んでいます)
2. 訳を埋めて、`data/titles_ja.json` に追記する
3. コミットすれば、次の更新から日本語の見出しが表示されます

翻訳APIを使わず、自分のClaudeで週に1回まとめて訳せば、費用は0円のままです。

### 情報源を増やす

`collect.py` の `SOURCES` に追記するだけです。

```python
{
    "id": "ppc",
    "name": "個人情報保護委員会(日本)",
    "full_name": "個人情報保護委員会",
    "country": "JP",
    "theme": "privacy",
    "lang": "ja",
    "site": "https://www.ppc.go.jp/",
    "feeds": ["https://www.ppc.go.jp/rss/news.xml"],   # 実在するフィードURLに置き換える
},
```

`index.html` の先頭にある `SOURCES` にも同じ `id` と名前を足すと、絞り込みに出てきます。

### ロシア関連の除外

`collect.py` の `EXCLUDE_KEYWORDS` に入っている語が見出しに含まれる項目は、取り込みません。
サイバー勧告には攻撃者としてロシアが名指しされるものがあるため、既定で除外しています。
必要に応じて語を足してください。

## 公開前に確認すること

- **各機関の利用規約とrobots.txt**:フィードの利用条件を一度確認してください。
  いずれも公的機関ですが、表示方法(見出しとリンクのみ)は守る前提です。
- **連絡先の記載**:`collect.py` の `USER_AGENT` にある連絡用メールアドレスを、実際のものに書き換えてください。
  取得元から連絡を受けられる状態にしておくのが礼儀であり、遮断を避けることにもつながります。
- **取得の頻度**:1日1回で十分です。頻度を上げると相手のサーバーに負担をかけます。
- **免責の表示**:`index.html` のフッターに記載済みです。内容を自分の言葉に直してください。
- **サイト名**:「サイバー勧告ウォッチ」は仮の名前です。公式機関と誤解されない名前にしてください。

## 次の段階(有料版を作るとき)

この構成のまま、次の順で足していけます。

1. メールでの通知(条件を登録した人に、新しい項目を知らせる)
2. 会員登録(Cloudflare D1 や Supabase の無料枠で始められます)
3. 決済(日本に戻ってから。当面は請求書払いでも成立します)

無料と有料の線引きは、「読むことは無料、見落とさないための通知とまとめは有料」が基本方針です。
