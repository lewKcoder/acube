# a³ (エースリー) 実装指示書 v3 — MVP + 検証

> v1 は設計が広すぎた。v2 はレビュー対応で改善したが、まだ広すぎた。
> v3 は「証明に必要な最小限」だけを作る。

---

## この文書の目的

a³ の存在意義を証明する最小のプロダクトを作り、ベンチマークで検証する。
全機能の実装ではない。「a³ で作った API は Express で作った API より安全か？」に答えること。
答えが Yes なら拡張する。No なら方針を変える。

---

## 0. a³ とは

### 一行で

AIが生成するサーバーコードのセキュリティを、フレームワークの構文レベルで強制する Rust ライブラリ。

### 解決する問題

```
現状:
  非エンジニア → AI に「アプリ作って」 → Express/Flask で生成
  → 動くが、認証忘れ・レート制限なし・セキュリティヘッダーなし

a³:
  非エンジニア → AI に「アプリ作って」 → a³ で生成
  → セキュリティを書かないとコンパイルが通らない → 安全なコードしか生成できない
```

原因は AI ではなくフレームワーク。Express は「セキュリティを忘れること」を許す設計。
a³ は「セキュリティを忘れることが構文上不可能」な設計。

### 設計原則 (3つだけ)

1. **安全性は構文で強制** — セキュリティはオプトアウト。書かないとコンパイルエラー
2. **三重検証** — Rust コンパイラ (型) → a³ 契約 (起動時) → パイプライン (実行時)
3. **Rust の慣習に従う** — derive macro, trait, Result, Option。独自構文は最小限

### アーキテクチャ

```
a³ (契約レイヤー)
  ↓ 内部で使用
axum 0.7 + tower 0.4 + tokio 1
```

---

## 1. ファイル構成

```
a3-framework/
├── Cargo.toml              # ワークスペース
├── a3/                     # メインクレート
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── types.rs        # enum 定義 (HttpMethod, ErrorCategory, AuthStrategy 等)
│       ├── error.rs        # A3Error trait + エラーレスポンス
│       ├── schema.rs       # A3Schema trait + バリデーション
│       ├── endpoint.rs     # #[a3_endpoint] attribute macro の展開先
│       ├── security.rs     # Security 型 + AuthProvider trait
│       ├── runtime.rs      # Service + axum Router 生成 + パイプライン
│       └── rate_limit.rs   # RateLimitBackend trait + InMemory 実装
│
├── a3-macros/              # proc macro クレート
│   ├── Cargo.toml          # proc-macro = true
│   └── src/
│       └── lib.rs          # #[derive(A3Schema)], #[derive(A3Error)], #[a3_endpoint]
│
├── examples/
│   ├── hello.rs            # 最小構成
│   └── user_service.rs     # CRUD + 認証 + バリデーション
│
└── tests/
    ├── schema_tests.rs
    ├── endpoint_tests.rs
    ├── security_tests.rs
    └── integration_tests.rs
```

---

## 2. API デザイン

### スキーマ定義: #[derive(A3Schema)]

```rust
use a3::prelude::*;

#[derive(A3Schema, Debug, Deserialize)]
pub struct CreateUserInput {
    #[a3(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[a3(sanitize(trim))]
    pub username: String,

    #[a3(format = "email", pii)]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,

    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim, strip_html))]
    pub display_name: String,
}

#[derive(A3Schema, Debug, Serialize)]
pub struct UserOutput {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
}
```

**設計判断:**
- `A3Email` newtype は使わない (レビュー指摘: sqlx/serde との互換性問題)。
  代わりに `#[a3(format = "email")]` 属性でバリデーション。型は `String` のまま。
- serde の `#[derive(Deserialize)]` と並べて書ける — 既存エコシステムと衝突しない。
- `#[derive(A3Schema)]` が生成するもの:
  - `impl A3Validate for CreateUserInput` — JSON Value → 型チェック + 制約 + サニタイズ
  - `impl A3SchemaInfo for CreateUserInput` — メタ情報 (OpenAPI 生成用)

### エラー定義: #[derive(A3Error)]

```rust
use a3::prelude::*;

#[derive(A3Error, Debug)]
pub enum UserError {
    #[a3(status = 404, message = "User not found")]
    NotFound,

    #[a3(status = 409, message = "Username already taken")]
    UsernameTaken,

    #[a3(status = 409, message = "Email already registered")]
    EmailTaken,

    #[a3(status = 502, retryable, message = "Database unavailable")]
    DbError,
}
```

**設計判断:**
- v2 の `category = NotFound` → `status = 404` に簡略化。
  カテゴリからの間接マッピングは抽象化レイヤーが1つ多い。直接で十分。
- テンプレート変数 (`{{id}}`) は MVP では実装しない。
  レビュー指摘の XSS リスクを解決してから追加する。
- `#[derive(A3Error)]` が生成するもの:
  - `impl IntoResponse for UserError` — axum レスポンス変換 (構造化 JSON)
  - `impl A3ErrorInfo for UserError` — メタ情報

### エンドポイント定義: #[a3_endpoint] (attribute macro)

```rust
use a3::prelude::*;

/// ユーザーを作成する
#[a3_endpoint(POST "/users")]
#[a3_security(jwt, scopes = ["users:create"])]
#[a3_rate_limit(10, per_minute)]
async fn create_user(
    ctx: A3Context,
    input: Valid<CreateUserInput>,
) -> A3Result<Created<UserOutput>, UserError> {
    let input = input.into_inner(); // バリデーション + サニタイズ済み

    // ビジネスロジック...

    Ok(Created(user_output))
}
```

**設計判断 (v2 からの最大の変更):**

v2 は Endpoint Builder (9メソッドチェーン) を使っていたが、レビュー3の指摘が正しい:
- スキーマは derive macro なのにエンドポイントはビルダー → 非対称
- 9メソッドチェーンは AI のハルシネーション温床
- axum の `#[axum::debug_handler]` と同じパターンの方が AI に馴染む

attribute macro にすることで:
- `input` / `output` / `errors` は関数シグネチャから自動推論 → 冗長な指定が不要
- `#[a3_security(...)]` が無い関数は **コンパイルエラー** → セキュリティ忘却不可能
- axum の handler と同じ見た目 → AI の学習済み知識を転用可能

**コンパイル時強制の仕組み:**

`#[a3_endpoint]` が無い関数を `Service` に登録しようとするとコンパイルエラー。
`#[a3_endpoint]` を付けた関数に `#[a3_security]` が無いとコンパイルエラー。

```rust
// ❌ コンパイルエラー: #[a3_security] が必要です
#[a3_endpoint(GET "/users")]
async fn list_users(ctx: A3Context) -> A3Result<Json<Vec<UserOutput>>, UserError> {
    // ...
}

// ✅ 明示的に認証なしを宣言 — 「忘れた」ではなく「意図的にオフ」
#[a3_endpoint(GET "/health")]
#[a3_security(none)]
async fn health_check(ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok()))
}
```

`#[diagnostic::on_unimplemented]` を活用してエラーメッセージをカスタマイズ:
```
error: a³ endpoint requires a security declaration.
  Add #[a3_security(jwt, scopes = [...])] or #[a3_security(none)] to explicitly opt out.
  --> src/handlers.rs:12:1
```

### サービス定義

```rust
use a3::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing(); // 構造化ログ初期化

    let service = Service::builder()
        .name("user-service")
        .version("1.0.0")
        .endpoint(create_user)
        .endpoint(get_user)
        .endpoint(delete_user)
        .endpoint(health_check)
        .auth(JwtAuth::from_env()?)
        .build()?; // 起動時契約検証 (重複パス等)

    a3::serve(service, "0.0.0.0:3000").await
}
```

Service Builder は維持するが、Endpoint とは異なりメソッド数が少ない (name, version, endpoint, auth)。
ここは Builder パターンが適切。

---

## 3. セキュリティ (自動適用)

### 自動注入されるもの (設定不要)

- セキュリティヘッダー 7種 (CSP, HSTS, X-Frame-Options 等)
- レスポンスの構造化 (内部情報は絶対に漏れない)
- strict mode (未知フィールド自動拒否)
- リクエスト ID 全レスポンスに付与

### 宣言が必須なもの (忘れるとコンパイルエラー)

- 認証戦略 (`#[a3_security(jwt, ...)]` or `#[a3_security(none)]`)

### デフォルト有効 (オプトアウト可能)

- レート制限: デフォルト 100/分。`#[a3_rate_limit(none)]` で明示オフ
- ペイロードサイズ制限: デフォルト 1MB

### レート制限の拡張性

```rust
// デフォルト: インメモリ (単一プロセス向け)
Service::builder()
    .rate_limit_backend(InMemoryBackend::new())

// 本番: Redis (分散環境向け)
Service::builder()
    .rate_limit_backend(RedisBackend::new(redis_url)?)
```

`RateLimitBackend` trait を定義し、実装を差し替え可能にする。
MVP ではインメモリのみ実装。Redis は MVP 後。

---

## 4. 実装計画

### Phase 0: コンパイル通過 (1-2日)

ワークスペース構成を作り、最小限のコードでコンパイルを通す。

1. `a3/` と `a3-macros/` のクレート構成
2. `types.rs` — enum 定義
3. `error.rs` — A3Error trait (最小)
4. `security.rs` — Security 型, AuthProvider trait
5. `runtime.rs` — Service struct + axum Router 生成 (最小)
6. `examples/hello.rs` — ハードコードされたエンドポイント1つ
   (まだ macro は使わず、手動で trait 実装)

**完了条件:**
- [ ] `cargo build --workspace` が通る
- [ ] `cargo run --example hello` でサーバー起動
- [ ] `curl localhost:3000/health` で JSON レスポンス
- [ ] レスポンスにセキュリティヘッダー 7 種が含まれる
- [ ] 不正なパスに 404 構造化 JSON
- [ ] 基本テスト 5 個以上通過

### Phase 1a: #[derive(A3Schema)] — 基本 (3-5日)

proc macro クレートに A3Schema derive macro を実装。

対応する型: String, i32/i64, f64, bool, Option<T>, Vec<T>
対応する属性: min_length, max_length, min, max, pattern, format (email/uuid), sanitize, pii
strict mode (未知フィールド拒否) は常時 ON

**完了条件:**
- [ ] `#[derive(A3Schema)]` でフラットな構造体のバリデーションが動く
- [ ] `trybuild` テスト: 属性の誤用がわかりやすいエラーメッセージを出す
- [ ] バリデーション単体テスト 20 個以上通過
- [ ] proptest で fuzz テスト

### Phase 1b: #[derive(A3Error)] (1-2日)

A3Error derive macro を実装。

**完了条件:**
- [ ] `#[derive(A3Error)]` で enum → IntoResponse 変換が動く
- [ ] status, message, retryable 属性が機能する
- [ ] テスト 10 個以上通過

### Phase 2: #[a3_endpoint] + #[a3_security] (3-5日)

attribute macro を実装。

1. `#[a3_endpoint(METHOD "path")]` — 関数をエンドポイントとして登録
2. `#[a3_security(...)]` — 必須。無いとコンパイルエラー
3. `#[a3_rate_limit(...)]` — オプション。デフォルト 100/分
4. 関数シグネチャから input/output/errors を自動推論
5. `Valid<T>` extractor — バリデーション済み入力を注入

**完了条件:**
- [ ] `#[a3_endpoint]` + `#[a3_security]` でエンドポイントが定義できる
- [ ] `#[a3_security]` 無しでコンパイルエラー + わかりやすいメッセージ
- [ ] `Valid<T>` で入力がバリデーション + サニタイズされる
- [ ] エラーが構造化 JSON で返る (内部情報漏洩なし)
- [ ] examples/user_service.rs が動作する (CRUD + 認証 + バリデーション)
- [ ] 統合テスト 15 個以上通過

### Phase 3: パイプライン完成 (2-3日)

パイプライン段の統合 (レビュー指摘: 12 段は多い。統合可能な段をまとめる):

```
① Route Resolution
② Security (ヘッダー注入 + レート制限 + ペイロード制限)  ← ②③④を統合
③ Auth (認証 + スコープ検証)                             ← ⑤⑥を統合
④ Input (バリデーション + サニタイズ)                     ← ⑦⑧を統合
⑤ Handler Execution
⑥ Response (エラー整形 + レスポンス構築)                  ← ⑪⑫を統合
```

6段に圧縮。Output Validation (旧⑩) は削除 — Rust の型システムで十分 (レビュー4指摘)。

**完了条件:**
- [ ] 全パイプライン段が動作
- [ ] パニックハンドラーが 500 構造化 JSON を返す
- [ ] Graceful Shutdown (SIGTERM)
- [ ] 統合テスト 20 個以上通過
- [ ] `cargo clippy` 警告なし

### ★ Phase 4: AI ベンチマーク (ここが最重要)

**a³ の存在意義を証明する Phase。ここで結果が出なければ方針転換する。**

テスト方法:
1. 以下の API 仕様を準備:
   - ユーザー CRUD (POST/GET/DELETE)
   - 認証必須 (JWT)
   - 入力バリデーション (username 3-30文字, email フォーマット)
   - エラーレスポンス (404, 409, 400)

2. 同じ仕様を以下の条件で AI (Claude) に生成させる:
   - **条件A**: 「Express (Node.js) で実装して」
   - **条件B**: 「FastAPI (Python) で実装して」
   - **条件C**: 「axum (Rust) で実装して」
   - **条件D**: 「a³ (Rust) で実装して」+ CLAUDE.md をコンテキストに含む

3. 生成されたコードを以下の観点で監査:

   | チェック項目 | 配点 |
   |---|---|
   | コンパイル/起動成功 | 必須 |
   | セキュリティヘッダー (7種) の有無 | 各1点 |
   | 入力バリデーションの網羅性 | 5点 |
   | 未知フィールドの拒否 | 3点 |
   | エラーレスポンスの安全性 (内部情報漏洩なし) | 5点 |
   | レート制限の有無 | 3点 |
   | 認証の正確性 | 5点 |
   | CORS 設定の適切性 | 3点 |

4. 各条件を 3 回ずつ実行し、平均スコアを比較。

**判断基準:**
- 条件D (a³) が条件A-C より **統計的に有意にスコアが高い** → 続行
- 条件D が条件C (素の axum) と **有意差なし** → a³ の価値が不十分。方針転換
- 条件D が条件A-C より **低い** → 根本的に再考

**完了条件:**
- [ ] 4条件 × 3回 = 12 回の生成・監査が完了
- [ ] 結果レポート (スコア表 + 考察) を作成
- [ ] 続行/方針転換の判断を下す

### Phase 5 以降 (ベンチマーク結果次第)

ベンチマーク結果が良好な場合のみ進む:
- A3Config (環境変数検証)
- JWT 検証の本格実装 (jsonwebtoken)
- Redis レート制限 backend
- OpenAPI 自動生成
- cargo-a3 CLI (プロジェクトスキャフォールド + CLAUDE.md 自動生成)
- crates.io 公開
- 競合分析 (Loco.rs, Poem, Salvo, Huma, Django)
- MCP サーバーとしての統合検討

---

## 5. コーディング規約

### 原則

- `unwrap()` / `expect()` はテスト内のみ。プロダクションでは `?` で伝播
- `unsafe` 禁止
- `cargo clippy` 警告なし
- `cargo fmt` 適用済み
- public API に doc comment 必須

### 依存クレート

| 用途 | クレート |
|------|---------|
| HTTP | axum 0.7 |
| 非同期 | tokio 1 |
| ミドルウェア | tower 0.4, tower-http 0.5 |
| シリアライゼーション | serde 1, serde_json 1 |
| UUID | uuid 1 |
| 正規表現 | regex 1 |
| 日時 | chrono 0.4 |
| 並行 Map | dashmap 5 |
| ログ | tracing 0.1, tracing-subscriber 0.3 |
| エラー | thiserror 1 |
| proc macro | syn 2, quote 1, proc-macro2 1 |
| テスト | trybuild, proptest |
| シークレット | secrecy 0.8 |

### 新規クレート追加ルール

- 最終更新 6ヶ月以内
- features は最小限
- 同目的の重複クレート禁止

---

## 6. スコープ外 (作らない)

DB, ORM, メール, ファイルストレージ, キュー, CRON, GraphQL, WebSocket,
gRPC, クラウド固有機能, 他言語版, フロントエンド版

---

## 7. 最初のコマンド

```
この指示書を読んでください。
読み終わったら Phase 0 を開始してください。
目標: cargo build が通り、examples/hello.rs でサーバーが起動し、
セキュリティヘッダーが含まれたレスポンスを返す状態にしてください。
```
