# Requirements Document - Burp Suite AI Extension

## 1. Overview
Burp SuiteのExtensionとして、LLMを活用してHTTPリクエスト/レスポンスを分析するツールを開発する。

## 2. Functional Requirements

### 2.1 Configuration Management
- **FR-001**: LLMのエンドポイントURLを設定画面から入力・保存できる
- **FR-002**: LLM APIキーを設定画面から安全に入力・保存できる
- **FR-003**: システムプロンプトを設定画面から編集・保存できる
- **FR-004**: 設定内容は永続化され、Burp Suite再起動後も保持される

### 2.2 AI Integration
- **FR-005**: Repeater画面から専用のボタンまたはコンテキストメニューでAI分析を実行できる
- **FR-006**: 選択されたHTTPリクエストとレスポンスのペアをLLMに送信できる
- **FR-007**: LLMからの応答を専用のパネルまたはダイアログで表示できる
- **FR-008**: AI分析実行中は進捗状態（処理中/完了/エラー）を表示する

### 2.3 User Interface
- **FR-009**: Extension設定画面はBurp SuiteのUIガイドラインに準拠する
- **FR-010**: AI応答表示は読みやすくフォーマットされる（マークダウン対応が望ましい）
- **FR-011**: エラーメッセージは適切にユーザーに通知される

## 3. Non-Functional Requirements

### 3.1 Security
- **NFR-001**: APIキーは安全に保存される（平文保存を避ける）
- **NFR-002**: LLMへの通信はHTTPS経由で行われる
- **NFR-003**: 機密情報を含む可能性があるHTTPデータの取り扱いに注意する

### 3.2 Performance
- **NFR-004**: AI分析は非同期で実行され、Burp SuiteのUIをブロックしない
- **NFR-005**: タイムアウト機能を実装し、長時間応答がない場合は適切に処理する

### 3.3 Compatibility
- **NFR-006**: Burp Suite Professional/Community Edition両方で動作する
- **NFR-007**: Java 11以上で動作する

### 3.4 Extensibility
- **NFR-008**: 複数のLLMプロバイダー（OpenAI、Anthropic等）に対応できる設計とする
- **NFR-009**: システムプロンプトはカスタマイズ可能で、様々な分析目的に対応できる

## 4. Constraints
- Burp Suite Extension APIの制限に準拠する
- JavaまたはPython（Jython）で実装する必要がある

## 5. User Stories

### US-001: 初期設定
**As a** セキュリティエンジニア  
**I want to** LLMの接続情報を設定する  
**So that** AI分析機能を利用できる

### US-002: リクエスト/レスポンス分析
**As a** ペネトレーションテスター  
**I want to** RepeaterのHTTPトラフィックをAIに分析させる  
**So that** 潜在的な脆弱性や改善点を発見できる

### US-003: カスタム分析
**As a** セキュリティアナリスト  
**I want to** システムプロンプトをカスタマイズする  
**So that** 特定の観点（SQLi、XSS等）に焦点を当てた分析ができる

## 6. Acceptance Criteria
- 設定画面からLLM接続情報を保存でき、次回起動時も保持される
- Repeaterから1クリックでAI分析を実行できる
- AI応答が5秒以内に表示される（LLMレスポンス時間を除く）
- エラー発生時は適切なメッセージが表示される