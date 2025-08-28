# Design Document - Burp Suite AI Extension

## 1. Architecture Overview

### 1.1 System Architecture
```
┌─────────────────────────────────────────────────────────┐
│                    Burp Suite                           │
│  ┌─────────────────┐  ┌──────────────────────────────┐ │
│  │    Repeater     │  │      AI Extension Tab        │ │
│  │                 │  │  ┌────────────────────────┐  │ │
│  │  [Analyze with  │  │  │   Configuration Panel  │  │ │
│  │      AI]        │  │  │  - Endpoint URL        │  │ │
│  │                 │  │  │  - API Key             │  │ │
│  └────────┬────────┘  │  │  - System Prompt       │  │ │
│           │           │  └────────────────────────┘  │ │
│           │           └──────────────────────────────┘ │
│           │                                             │
│  ┌────────▼────────────────────────────────────────┐   │
│  │             Extension Core                       │   │
│  │  ┌────────────┐  ┌─────────────┐  ┌──────────┐ │   │
│  │  │   Config    │  │   Request   │  │    UI    │ │   │
│  │  │  Manager    │  │  Processor  │  │ Manager  │ │   │
│  │  └──────┬─────┘  └──────┬──────┘  └──────────┘ │   │
│  │         │                │                       │   │
│  │  ┌──────▼────────────────▼──────┐               │   │
│  │  │        LLM Client             │               │   │
│  │  │  - OpenAI Provider            │               │   │
│  │  │  - Anthropic Provider         │               │   │
│  │  └───────────────┬───────────────┘               │   │
│  └──────────────────┼───────────────────────────────┘   │
└────────────────────┼─────────────────────────────────┘
                     │
                     ▼
              ┌──────────────┐
              │  LLM API     │
              │  (External)  │
              └──────────────┘
```

### 1.2 Component Responsibilities

#### Extension Core
- エントリーポイント（BurpExtender）
- 各コンポーネントの初期化と管理
- Burp Suite APIとの統合

#### Configuration Manager
- 設定の読み込み・保存
- APIキーの暗号化・復号化
- 設定変更の通知

#### Request Processor
- HTTPリクエスト/レスポンスの取得
- LLMへの送信用フォーマット変換
- 分析結果の処理

#### UI Manager
- Extension設定タブの管理
- Repeaterへのボタン追加
- 分析結果表示ダイアログ

#### LLM Client
- 複数LLMプロバイダーの抽象化
- API通信の実装
- エラーハンドリングとリトライ

## 2. Data Flow

### 2.1 Configuration Flow
```
User → Configuration Panel → Config Manager → Encrypted Storage
```

### 2.2 Analysis Flow
```
1. User clicks "Analyze with AI" in Repeater
2. Request Processor extracts HTTP data
3. LLM Client formats and sends to API
4. Response displayed in dialog/panel
```

## 3. Interface Design

### 3.1 Configuration Tab
```
┌─────────────────────────────────────────┐
│ AI Analyzer Configuration               │
├─────────────────────────────────────────┤
│ LLM Provider: [Dropdown: OpenAI/Claude] │
│                                         │
│ Endpoint URL:                           │
│ [_____________________________________] │
│                                         │
│ API Key:                                │
│ [*************************************] │
│                                         │
│ System Prompt:                          │
│ ┌───────────────────────────────────┐   │
│ │ Analyze HTTP requests/responses   │   │
│ │ for security vulnerabilities...   │   │
│ │                                   │   │
│ └───────────────────────────────────┘   │
│                                         │
│ [Test Connection] [Save] [Reset]        │
└─────────────────────────────────────────┘
```

### 3.2 Analysis Result Dialog
```
┌─────────────────────────────────────────┐
│ AI Analysis Result                   [X]│
├─────────────────────────────────────────┤
│ Request: GET /api/users/123             │
│ Status: 200 OK                          │
├─────────────────────────────────────────┤
│ Analysis:                               │
│ ┌───────────────────────────────────┐   │
│ │ Potential Issues Found:           │   │
│ │                                   │   │
│ │ 1. Missing authentication header  │   │
│ │ 2. User ID exposed in URL         │   │
│ │ 3. No rate limiting detected      │   │
│ │                                   │   │
│ │ Recommendations:                  │   │
│ │ - Implement JWT authentication    │   │
│ │ - Use UUIDs instead of sequential │   │
│ │   IDs                             │   │
│ └───────────────────────────────────┘   │
│                                         │
│ [Copy to Clipboard] [Export] [Close]    │
└─────────────────────────────────────────┘
```

## 4. Implementation Details

### 4.1 Technology Stack
- **Language**: Java (Burp Suite native)
- **Build Tool**: Gradle
- **Dependencies**:
  - Burp Suite Extension API
  - OkHttp (HTTP client)
  - Gson (JSON processing)
  - Java Cryptography Architecture (JCA) for encryption

### 4.2 Package Structure
```
com.airis.burp.ai/
├── BurpExtender.java           # Main entry point
├── config/
│   ├── ConfigManager.java      # Configuration management
│   ├── ConfigModel.java        # Configuration data model
│   └── SecureStorage.java      # Encrypted storage
├── ui/
│   ├── ConfigurationTab.java   # Settings UI
│   ├── AnalysisDialog.java     # Result display
│   └── RepeaterIntegration.java# Repeater button
├── core/
│   ├── RequestProcessor.java   # HTTP data processing
│   └── AnalysisEngine.java     # Core logic
├── llm/
│   ├── LLMClient.java          # Abstract LLM interface
│   ├── OpenAIClient.java       # OpenAI implementation
│   └── AnthropicClient.java    # Anthropic implementation
└── utils/
    ├── HttpUtils.java          # HTTP utilities
    └── CryptoUtils.java        # Encryption utilities
```

### 4.3 Data Models

#### Configuration Model
```java
public class ConfigModel {
    private String provider;        // "openai" | "anthropic"
    private String endpoint;        // API endpoint URL
    private String encryptedApiKey; // Encrypted API key
    private String systemPrompt;    // System prompt text
}
```

#### Analysis Request Model
```java
public class AnalysisRequest {
    private String method;
    private String url;
    private Map<String, String> headers;
    private String body;
    private int statusCode;
    private String responseBody;
}
```

#### Analysis Response Model
```java
public class AnalysisResponse {
    private String analysis;        // AI analysis text
    private List<Finding> findings; // Structured findings
    private long responseTime;      // Analysis duration
}
```

## 5. Security Considerations

### 5.1 API Key Protection
- AES-256暗号化を使用
- マスターキーはユーザー固有の値から生成
- メモリ内でのキー保護

### 5.2 Data Handling
- センシティブデータの自動マスキング機能
- HTTPSのみでの通信
- ローカルストレージへのログ出力制限

### 5.3 Input Validation
- URL形式の検証
- APIレスポンスのサニタイゼーション
- システムプロンプトの長さ制限

## 6. Error Handling

### 6.1 Network Errors
- 接続タイムアウト: 30秒
- リトライ: 最大3回（指数バックオフ）
- オフライン時の適切なメッセージ表示

### 6.2 API Errors
- Rate limit対応
- 認証エラーの明確な通知
- レスポンスフォーマットエラーの処理

## 7. Testing Strategy

### 7.1 Unit Tests
- 各コンポーネントの独立したテスト
- モックを使用したLLM APIテスト
- 暗号化/復号化の検証

### 7.2 Integration Tests
- Burp Suite APIとの統合テスト
- エンドツーエンドのワークフローテスト
- 異なるLLMプロバイダーの切り替えテスト

### 7.3 Manual Testing
- UI/UXの確認
- 実際のHTTPトラフィックでのテスト
- パフォーマンステスト

## 8. Performance Optimization

### 8.1 非同期処理
- SwingWorkerを使用したバックグラウンド処理
- UIの応答性維持
- プログレスバーの表示

### 8.2 キャッシング
- 設定のメモリキャッシュ
- LLMレスポンスの一時キャッシュ（オプション）

### 8.3 リソース管理
- HTTP接続プーリング
- メモリ効率的なデータ構造
- 適切なスレッド管理

## 9. Future Enhancements

### 9.1 Phase 2
- バッチ分析機能
- カスタムプロンプトテンプレート
- 分析履歴の保存と検索

### 9.2 Phase 3
- 他のBurp Suiteツールとの統合（Scanner, Intruder）
- レポート生成機能
- チーム共有機能