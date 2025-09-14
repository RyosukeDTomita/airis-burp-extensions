# Vibe Codingの振り返り

このプロジェクトを通じて得られた技術的な学びと開発プロセスの振り返りをまとめます。特に試行錯誤した部分とBurp Extensions開発のノウハウを中心に記録します。
AIの経験をAIが活かしたり，人間が同じ場所で詰まった場合に参考にすることを目的としています。

## 1. 仕様駆動開発の実践

### 学び
- **段階的な仕様明確化の重要性**: requirements.md → design.md → tasks.md の流れで仕様を段階的に詳細化することで、実装前に要件の抜け漏れを発見できました
- **ドキュメントファーストアプローチ**: 実装前にドキュメントを作成することで、全体像を把握しやすくなり、手戻りを減らすことができました

### 改善点
- 初期の要件定義で「Repeater統合」が明記されていたにも関わらず、実装タスクから漏れていました
- UI設計の詳細が不足していたため、実装時に判断が必要な箇所がありました

## 2. Test-Driven Development (TDD) の徹底

### 学び
- **Red-Green-Refactorサイクル**: 各コンポーネントに対してテストを先に書くことで、インターフェースが明確になり、実装の品質が向上しました
- **モックを活用したユニットテスト**: 外部依存（LLM API、Burp API）をモック化することで、高速で安定したテストが実現できました
- **統合テストの重要性**: 個々のコンポーネントが正しく動作しても、統合時に問題が発生する可能性があることを学びました

### 実践例
```java
// テストファースト - まずテストを書く
@Test
public void testEncryptDecrypt() {
    String plainText = "test-api-key";
    String encrypted = storage.encrypt(plainText);
    String decrypted = storage.decrypt(encrypted);
    assertEquals(plainText, decrypted);
}

// その後に実装
public String encrypt(String plainText) {
    // 実装
}
```

## 3. 技術選定の試行錯誤 - 3回の言語変更

### 試行錯誤の経緯
1. **Java → Python(Jython)**: 「やっぱりJavaでなくPython(Jython)で作りたい」
2. **Python(Jython) → Java**: 「JythonってPython2系しかつかえないんだね。さすがにPython2系はしぶい」

この変更により、全ドキュメント（requirements.md、design.md、tasks.md）を3回書き直しました。

### 各言語の特性と制約

#### Java
- **メリット**: 完全なBurp Suite API対応、型安全性、豊富なライブラリ
- **デメリット**: ボイラープレートコードが多い、開発速度が遅い
- **対象**: Professional/Community両対応

#### Jython
- **メリット**: Python文法、Javaライブラリへのアクセス
- **デメリット**: Python 2.7のみ対応（致命的制約）
- **対象**: Professional/Community両対応

#### CPython
- **メリット**: Python 3対応、豊富なライブラリ
- **デメリット**: Professional版のみ対応
- **対象**: Professional版のみ

### 学んだ教訓
- **要件確認の重要性**: Community版対応が必須要件だったため、最終的にJavaが唯一の選択肢
- **制約調査の必要性**: 技術選定前に全ての制約を洗い出すべき

## 4. Burp Suite Extension開発の詳細ノウハウ

### 必須パッケージとライブラリ

#### 開発環境構築
```bash
# Java 8 (Burp Suiteとの互換性)
java -version  # openjdk version "1.8.0_xxx"

# Maven使用（build.xmlでJARパッケージ）
```

#### 必要な依存関係
```xml
<!-- pom.xml相当 - 実際はbuild.xmlを使用 -->
<dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>4.13.2</version>
</dependency>
```

#### 外部ライブラリ（HTTP通信）
- **OkHttp**: HTTP通信に使用したかったが、Burp Suite環境の制約で標準JavaのHttpURLConnectionを使用
- **Jackson**: JSONパースに使用予定だったが、依存関係を避けるため手動実装

### Burp Suite API の詳細理解

#### 必須実装事項
```java
// 1. パッケージ名は必ず 'burp'
package burp;

// 2. 必須インターフェース
public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 拡張機能の登録処理
        callbacks.setExtensionName("AI Security Analyzer");
    }
}
```

#### 大きなつまずきポイント - パッケージ名の制約
**Error**: `java.lang.Exception: Extension class is not a recognized type`

```java
// ❌ 最初の間違った実装
package com.airis.burp.ai;  // これが原因でエラー
public class BurpExtender implements IBurpExtender { }

// ✅ 正しい実装
package burp;  // 必須: burpパッケージ
public class BurpExtender implements IBurpExtender { }
```

#### UI統合の実装詳細
```java
// ITabインターフェースの実装
public class ConfigurationTab extends JPanel implements ITab {
    @Override
    public String getTabCaption() {
        return "AI Analyzer Config";
    }
    
    @Override
    public Component getUiComponent() {
        return this;  // JPanelを返す
    }
}
```

### JAR作成の試行錯誤

#### 最初の失敗 - クラスパス問題
```xml
<!-- build.xml - 最初の失敗バージョン -->
<jar destfile="ai-security-analyzer.jar">
    <fileset dir="build/classes"/>
    <!-- ❌ メインクラスが見つからない -->
</jar>
```

#### 解決策 - 正しいJAR構成
```xml
<!-- 正しいbuild.xml -->
<jar destfile="ai-security-analyzer.jar">
    <fileset dir="build/classes"/>
    <manifest>
        <attribute name="Main-Class" value="burp.BurpExtender"/>
    </manifest>
</jar>
```

### Repeater統合の実装漏れと解決

#### 問題の発覚
「APIキーをセットまでしたんだけど、AIにburpのリクエスト、レスポンスを入れる方法がわからない」

#### 原因分析
- requirements.mdには「Repeaterタブでの右クリックメニュー」が記載されていた
- しかし、tasks.mdからこの機能が漏れていた
- 結果として、設定UIだけでAnalyze機能が実装されていなかった

#### 解決実装
```java
// IContextMenuFactoryの実装追加
public class ContextMenuProvider implements IContextMenuFactory {
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE) {
            
            JMenuItem analyzeItem = new JMenuItem("Analyze with AI");
            analyzeItem.addActionListener(e -> analyzeMessage(invocation));
            menuItems.add(analyzeItem);
        }
        
        return menuItems;
    }
}
```

## 5. セキュリティ考慮事項

### 学び
- **APIキーの安全な保存**: AES-256暗号化を使用してAPIキーを保護
- **センシティブデータのサニタイゼーション**: パスワードやトークンを自動的に除去する仕組みの実装
- **エラーメッセージの適切な処理**: APIキーなどの機密情報がエラーメッセージに含まれないよう注意

### 実装例
```java
// パスワードパターンのマスキング
private static final Pattern PASSWORD_PATTERN = Pattern.compile(
    "(password|pwd|pass)[\"\\s]*[=:][\"\\s]*([^&\\s,}]+)", 
    Pattern.CASE_INSENSITIVE
);
```

## 6. 暗号化・データ保護での試行錯誤

### Base64デコードエラーの解決
**Error**: `java.lang.IllegalArgumentException: Illegal base64 character`

#### 問題の原因
```java
// ❌ 空文字列をBase64デコードしようとしてエラー
public String decryptApiKey() {
    String encryptedKey = loadEncryptedKey();  // 空文字列を返す
    return secureStorage.decrypt(encryptedKey);  // エラー発生
}
```

#### 解決策
```java
// ✅ null/空文字チェックを追加
public String decryptApiKey() {
    String encryptedKey = loadEncryptedKey();
    if (encryptedKey == null || encryptedKey.trim().isEmpty()) {
        return "";  // 空文字列を返す
    }
    return secureStorage.decrypt(encryptedKey);
}
```

### AES暗号化実装の詳細
```java
public class SecureStorage {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    
    // ❌ 最初の実装: 固定IV（セキュリティリスク）
    // ✅ 最終実装: ランダムIV生成
    public String encrypt(String plainText) {
        // セキュアランダムでIVを生成
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        // ...
    }
}
```

## 7. 開発プロセスの振り返り

### 試行錯誤から得た教訓

#### 良かった点
1. **TDDの徹底**: 全31タスクをRed-Green-Refactorで実装
   - テストのおかげでリファクタリングが安全に行えた
   - バグの早期発見に効果的だった

2. **モジュール設計**: 責任を明確に分離したコンポーネント設計
   ```
   BurpExtender (Entry Point)
   ├── ConfigurationTab (UI)
   ├── ConfigManager (設定管理)
   ├── SecureStorage (暗号化)
   ├── AnalysisEngine (分析エンジン)
   └── LLMClient (API通信)
   ```

3. **エラーハンドリング**: 各層で適切な例外処理を実装

#### 改善すべき点と失敗分析
1. **要件の実装漏れ**: Repeater統合が最初のリリースで漏れていた
   - **原因**: requirements.md → tasks.mdの変換時にタスクが漏れた
   - **対策**: 要件とタスクの対照表作成が必要

2. **E2Eテストの不足**: 実際のBurp Suite環境でのテストが不十分
   - **問題**: ユニットテストは通ったが、実際のBurpで動かない部分があった
   - **対策**: 早期の手動テストが重要

3. **ユーザビリティの考慮不足**: 使い方がわかりにくい
   - **問題**: 「APIキーをセットしたけど使い方がわからない」
   - **対策**: ユーザージャーニーの設計が必要

### 特に苦労した技術的問題

#### 1. JSON手動パースの実装
外部ライブラリを避けるため、OpenAI APIレスポンスを手動でパース：

```java
// Jackson使いたかったが依存関係を避けて手動実装
private String extractContentFromResponse(String response) {
    // "content":"..." を正規表現で抽出
    Pattern pattern = Pattern.compile("\"content\"\\s*:\\s*\"([^\"\\\\]*(\\\\.[^\"\\\\]*)*)\"");
    // エスケープ文字の処理も必要
}
```

#### 2. Swing UIのレイアウト問題
GridBagLayoutの制約設定で苦労：

```java
// ❌ 最初: レイアウトが崩れる
gbc.fill = GridBagConstraints.HORIZONTAL;
gbc.weightx = 0.0;  // これが問題

// ✅ 解決: 適切な重み付け
gbc.fill = GridBagConstraints.HORIZONTAL;
gbc.weightx = 1.0;  // 水平方向に拡張
```

#### 3. Burp Suite API の制約理解
- Community版とProfessional版のAPI差異を理解するのに時間がかかった
- コールバック登録のタイミング問題で苦労した

## 7. 技術的な発見

### Base64エンコーディングの注意点
- 空文字列のBase64デコードはエラーになるため、事前チェックが必要
- 暗号化前後のエンコーディング処理は慎重に実装する必要がある

### Swing UIの実装
- GridBagLayoutを使用した柔軟なレイアウト
- イベントハンドリングの適切な実装
- UIとビジネスロジックの分離

### JAR作成時の考慮事項
- 依存ライブラリの適切なパッケージング
- マニフェストファイルの設定
- クラスパスの管理

## 8. インストール・配布に関する学び

### JAR作成とAntビルドスクリプト

#### 実際に使用したbuild.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project name="ai-security-analyzer" default="jar" basedir=".">
    
    <property name="src.dir" value="src"/>
    <property name="build.dir" value="build"/>
    <property name="classes.dir" value="${build.dir}/classes"/>
    <property name="jar.file" value="ai-security-analyzer.jar"/>
    
    <path id="classpath">
        <fileset dir="lib" includes="**/*.jar" erroronmissingdir="false"/>
        <!-- JUnit for testing -->
        <pathelement location="lib/junit-4.13.2.jar"/>
        <pathelement location="lib/hamcrest-core-1.3.jar"/>
    </path>
    
    <target name="init">
        <mkdir dir="${classes.dir}"/>
    </target>
    
    <target name="compile" depends="init">
        <javac srcdir="${src.dir}" 
               destdir="${classes.dir}" 
               classpathref="classpath"
               includeantruntime="false"
               target="1.8"
               source="1.8"/>
    </target>
    
    <target name="jar" depends="compile">
        <jar destfile="${jar.file}">
            <fileset dir="${classes.dir}"/>
        </jar>
    </target>
    
    <target name="test" depends="compile">
        <junit printsummary="yes" haltonfailure="yes">
            <classpath>
                <path refid="classpath"/>
                <pathelement location="${classes.dir}"/>
            </classpath>
            
            <formatter type="plain"/>
            
            <batchtest fork="yes" todir="${build.dir}">
                <fileset dir="${classes.dir}">
                    <include name="**/*Test.class"/>
                </fileset>
            </batchtest>
        </junit>
    </target>
    
    <target name="clean">
        <delete dir="${build.dir}"/>
        <delete file="${jar.file}"/>
    </target>
    
</project>
```

#### 学んだパッケージ管理のコツ
1. **外部依存の最小化**: Burp Suite環境で動作する最小限の依存関係のみ使用
2. **Java 8互換性**: target="1.8" source="1.8" の指定が重要
3. **テストライブラリの分離**: JUnitは開発時のみ必要、JARには含めない

### 実際のBurp Suiteインストール手順

#### Extension導入の実際の流れ
```bash
# 1. JARファイル作成
ant jar

# 2. Burp Suiteでの導入
# Extensions > Installed > Add > Java > Select JAR file
```

#### インストール時のトラブルシューティング
- **Error**: "Extension class is not a recognized type"
  - **解決**: パッケージ名を `burp.BurpExtender` に変更
- **Error**: "NoClassDefFoundError"
  - **解決**: 依存ライブラリをJARに含める、または標準ライブラリのみ使用

## 9. 今後の改善提案（実体験ベース）

### 開発プロセスの改善
1. **要件追跡マトリックス**: requirements.md ↔ tasks.md の対応表作成
2. **早期プロトタイピング**: UI設計は早期にモックアップを作成
3. **ユーザーテスト**: 開発者以外による動作確認の実施

### 技術的改善
1. **モジュール分割の再検討**: 現在の設計でも十分だが、より細かい責務分離も可能
2. **設定の永続化**: 現在はメモリ内保存、ファイルベース永続化の検討
3. **非同期処理**: LLM API呼び出しの非同期化でUI応答性向上

### 配布・運用の改善
```bash
# CI/CDパイプライン例
# .github/workflows/build.yml
name: Build and Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - uses: actions/setup-java@v2
      with:
        java-version: '8'
    - run: ant test
    - run: ant jar
    - uses: actions/upload-artifact@v2
      with:
        name: extension-jar
        path: ai-security-analyzer.jar
```

## まとめ - リアルな開発体験から

このプロジェクトは、理論と実践のギャップを強く実感させる経験でした：

### 最も価値のあった学び
1. **TDD の威力**: テストがあることでリファクタリングが怖くなくなった
2. **パッケージ制約の重要性**: Burp Suiteの `burp` パッケージ制約など、環境固有の制約は事前調査必須
3. **ユーザビリティの盲点**: 機能実装と使い方の間にはギャップがある

### 最も苦労した部分
1. **言語選択の迷い**: Java ↔ Jython ↔ Java の3回変更
2. **Burp Suite環境の理解**: 独特のAPI制約とパッケージ要件
3. **要件漏れ**: 最終的に一番重要な機能が抜けていた

### 次に同様のプロジェクトを行うなら
1. **環境制約の事前調査**: 3時間かけても技術選択を確実にする
2. **プロトタイプファースト**: 仕様書よりも先に動くものを作る
3. **ユーザージャーニー設計**: 機能実装前に「どう使うか」を明確にする

この経験により、仕様駆動開発とTDDの価値は確認できましたが、同時に実環境での動作確認とユーザビリティ検証の重要性も痛感しました。理論だけでなく、実践での試行錯誤こそが真の学習につながることを改めて実感した次第です。

## 10. Burp Suite右クリックメニュー統合とJSONエラー処理の学び

### コンテキストメニュー統合での試行錯誤

#### 問題1: 右クリックメニューが表示されない
**症状**: コンテキストメニューファクトリーを登録したがメニューが表示されない

**原因分析と解決**:
```java
// ❌ 最初の実装: 間違ったコンテキスト値
byte CONTEXT_REPEATER_REQUEST = 3;
byte CONTEXT_REPEATER_RESPONSE = 4;

// ✅ 実際のBurp Suite API値（ログで確認）
byte CONTEXT_MESSAGE_EDITOR_REQUEST = 0;
byte CONTEXT_MESSAGE_VIEWER_REQUEST = 6;
```

**学んだこと**:
- Burp Suite APIの定数値は実際の動作環境で確認が必要
- デバッグログを追加して実際の値を特定する手法が有効
- ドキュメント通りの値と実装が異なることがある

#### 問題2: ユーザビリティ - メニュー階層が深い
**最初の実装**: `右クリック → Extensions → AI Security Analyzer → Analyze with AI`

**改善後**: `右クリック → Extensions → AI Security Analyzer`（直接実行）

```java
// メニュー項目名の変更でクリック数を削減
JMenuItem analyzeMenuItem = new JMenuItem("AI Security Analyzer"); // 直接実行
// 従来: new JMenuItem("Analyze with AI"); // サブメニューが必要
```

**UX改善の学び**:
- 操作ステップ数の最小化は重要なUX改善要素
- メニュー名を機能名にすることで直接実行を暗示
- ユーザーの指摘から改善点を発見する重要性

### JSON API通信での重要な学び

#### 重大な問題: JSONパースエラーの解決
**Error**: `HTTP 400 Error: We could not parse the JSON body of your request`

**根本原因**: 二重JSONエスケープ問題
```java
// ❌ 問題のあるコード（二重エスケープ）
private String formatHttpData(AnalysisRequest request) {
    // この中でescapeJson()を呼び出し
    data.append(escapeJson(request.getBody()));
    return data.toString();
}

// formatRequest()でさらにescapeJsonを適用
json.append("\"content\": \"").append(escapeJson(formatHttpData(request))).append("\"");
// 結果: \\\"hello\\\" → \\\\\\\"hello\\\\\\\" (二重エスケープ)
```

**解決策**: エスケープ責任の明確化
```java
// ✅ 修正版: 一箇所でのみエスケープ
private String formatHttpData(AnalysisRequest request) {
    // エスケープしない生データを返す
    data.append(request.getBody()); // escapeJson削除
    return data.toString();
}

// formatRequest()で一回だけエスケープ
json.append("\"content\": \"").append(escapeJson(formatHttpData(request))).append("\"");
```

#### JSONエスケープの実装改良
```java
// ❌ 不完全なエスケープ実装
private String escapeJson(String text) {
    return text.replace("\"", "\\\"").replace("\n", "\\n");
}

// ✅ 包括的なエスケープ実装
private String escapeJson(String text) {
    if (text == null) return "";
    return text.replace("\\", "\\\\")  // Must be first!
               .replace("\"", "\\\"")
               .replace("\n", "\\n")
               .replace("\r", "\\r")
               .replace("\t", "\\t")
               .replace("\b", "\\b")
               .replace("\f", "\\f");
}
```

**重要な学び**:
1. **バックスラッシュのエスケープが最初**: `\\` → `\\\\` の変換を最初に行わないと他のエスケープが壊れる
2. **エスケープ責任の単一化**: データ変換は一箇所でのみ行う
3. **デバッグ出力の価値**: 実際のJSON文字列をログ出力してエラーを特定

### API通信のエラーハンドリング改良

#### エラーレスポンスの適切な処理
```java
// ❌ エラー時にgetInputStream()でIOException
try (BufferedReader br = new BufferedReader(
        new InputStreamReader(connection.getInputStream(), "utf-8"))) {
    // 400エラー時にIOExceptionが発生
}

// ✅ エラーレスポンスも適切に読み取り
int responseCode = connection.getResponseCode();
BufferedReader br = null;
try {
    if (responseCode >= 200 && responseCode < 300) {
        br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"));
    } else {
        br = new BufferedReader(new InputStreamReader(connection.getErrorStream(), "utf-8"));
    }
    // エラー内容を読み取ってユーザーに表示
} finally {
    if (br != null) br.close();
}
```

#### ユーザー向けエラーメッセージの改良
```java
// ❌ 技術的すぎるエラーメッセージ
response.setAnalysis(""); // 空文字列、何が問題かわからない

// ✅ ユーザーフレンドリーなエラーメッセージ
response.setAnalysis("Configuration validation failed. Please check your API endpoint and key in the AI Security Analyzer tab.");
response.setAnalysis("API request failed: " + e.getMessage());
```

### デバッグとログ出力の戦略

#### 効果的なデバッグ実装
```java
private boolean debugMode = true; // 開発時はtrue

if (debugMode) {
    System.out.println("API Endpoint: " + endpoint);
    System.out.println("API Key configured: " + (!apiKey.isEmpty()));
    System.out.println("Full JSON request:");
    System.out.println(jsonRequest); // ★完全なJSONを出力
    System.out.println("--- End of JSON request ---");
}
```

**デバッグ設計の学び**:
1. **完全な情報出力**: 省略せずフルデータを出力
2. **区切り文字の重要性**: ログの境界を明確化
3. **段階的情報**: 設定状態 → リクエスト → レスポンスの順序

### UI改善の実装詳細

#### 結果表示ダイアログの改良
```java
// ❌ 基本的なダイアログ
JDialog resultDialog = new JDialog();
resultDialog.setTitle("結果");
resultDialog.add(new JTextArea(result));

// ✅ ユーザビリティを考慮したダイアログ
JDialog resultDialog = new JDialog();
resultDialog.setTitle("AI Security Analysis Results");
resultDialog.setSize(1000, 700); // 十分なサイズ
resultDialog.setLocationRelativeTo(null); // 中央配置

JTextArea resultArea = new JTextArea(result);
resultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12)); // 等幅フォント
resultArea.setMargin(new Insets(10, 10, 10, 10)); // 適切な余白

// コピーボタンの追加
JButton copyButton = new JButton("Copy to Clipboard");
copyButton.addActionListener(e -> {
    Toolkit.getDefaultToolkit().getSystemClipboard()
        .setContents(new StringSelection(result), null);
});
```

### 学んだ重要な教訓

#### 1. API統合時の段階的デバッグ
1. **設定確認**: エンドポイント・APIキーの存在
2. **リクエスト構造**: 送信JSONの完全性
3. **レスポンス処理**: エラーレスポンスの適切な処理
4. **ユーザー表示**: 分かりやすいエラーメッセージ

#### 2. JSON処理の落とし穴
- **二重エスケープ**: 最も陥りやすい罠
- **エスケープ順序**: バックスラッシュを最初に処理
- **責任の分離**: エスケープは一箇所でのみ

#### 3. UX設計の重要性
- **操作ステップの最小化**: 4クリック → 3クリック
- **直感的なメニュー名**: "Analyze with AI" → "AI Security Analyzer"
- **適切なフィードバック**: 処理状況とエラー内容の明示

#### 4. 実装とテストのギャップ
- **環境固有の制約**: Burp Suite APIの実際の値
- **実際のAPI動作**: ドキュメントと実装の差異
- **ユーザー視点のテスト**: 開発者以外による操作確認

この学びにより、外部APIとの統合、特にセキュリティツールとの連携において重要な実装パターンとデバッグ手法を習得できました。

## 11. Montoya API移行による技術的な学び

### 背景：なぜMontoya APIへの移行が必要だったか

Burp Suiteには2つの拡張機能API が存在します：
1. **Legacy Extender API**: 従来のIBurpExtenderインターフェース
2. **Montoya API**: 2022年から導入された新しいAPI

当初は古いExtender APIで実装していましたが、「motoya-api」への移行要求を受けて、新しいMontoya APIへの全面移行を実施しました。

### Montoya API移行での主要な変更点

#### 1. 依存関係の変更

```gradle
// 以前：手動でJARファイルを管理
compileOnly files('lib/burp-extender-api.jar')

// 現在：Maven Centralから自動取得
compileOnly 'net.portswigger.burp.extensions:montoya-api:+'
```

**学び**：
- Maven Centralを使うことで依存関係管理が大幅に簡素化
- バージョン管理が容易になり、最新APIへの追従が簡単に

#### 2. Java バージョンの制約

```gradle
// 以前：Java 21を使用
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

// 現在：Java 17以下が必須
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17) // Montoya API requires Java 17 or lower
    }
}
```

**学び**：
- Burp Suite自体のJavaバージョン制約を考慮する必要性
- 新しいAPIでも互換性のために古いJavaバージョンが必要な場合がある

#### 3. エントリーポイントの変更

```java
// Legacy API
public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("airis");
    }
}

// Montoya API
public class MontoyaExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("airis");
    }
}
```

**学び**：
- より直感的なメソッド名（registerExtenderCallbacks → initialize）
- オブジェクト指向的なAPI設計（api.extension().setName() のようなメソッドチェーン）

#### 4. ロギングAPIの改善

```java
// Legacy API
callbacks.printOutput("Message");
callbacks.printError("Error");

// Montoya API
api.logging().logToOutput("Message");
api.logging().logToError("Error");
```

**学び**：
- より明確なメソッド名で意図が分かりやすい
- ロギング専用のAPIオブジェクトで責務が明確

#### 5. コンテキストメニュー実装の変更

```java
// Legacy API
public class Factory implements IContextMenuFactory {
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        // メニューアイテムの作成
    }
}

// Montoya API
public class Provider implements ContextMenuItemsProvider {
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // より汎用的なComponent型を返す
    }
}
```

**学び**：
- より柔軟なUI実装が可能（JMenuItemに限定されない）
- イベントオブジェクトがより豊富な情報を提供

#### 6. HTTP リクエスト/レスポンスの扱い

```java
// Legacy API
IHttpRequestResponse message = invocation.getSelectedMessages()[0];
byte[] request = message.getRequest();
byte[] response = message.getResponse();

// Montoya API
HttpRequestResponse message = event.selectedRequestResponses().get(0);
HttpRequest request = message.request();
HttpResponse response = message.response();
// 型安全で、toString()などのメソッドが使える
```

**学び**：
- バイト配列から型安全なオブジェクトへ
- より直感的なメソッド名とアクセス方法
- null安全性の向上（hasResponse()メソッドなど）

### 移行戦略の学び

#### 1. 後方互換性の維持

```java
// 両方のAPIをサポートする設計
public class RepeaterContextMenuFactory 
    implements IContextMenuFactory,     // Legacy API
               ContextMenuItemsProvider { // Montoya API
    
    // コンストラクタで使用するAPIを判定
    public RepeaterContextMenuFactory(IBurpExtenderCallbacks callbacks, ...) {
        // Legacy API用
    }
    
    public RepeaterContextMenuFactory(..., MontoyaApi api) {
        // Montoya API用
    }
}
```

**学び**：
- 段階的移行のために両方のAPIをサポートする設計が有効
- インターフェースの多重実装で柔軟な対応が可能

#### 2. スタブクラスの活用

```java
// コンパイル用のスタブを作成
package burp;
public interface IBurpExtender {
    void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
}
```

**学び**：
- 古いAPIのインターフェースをスタブとして残すことでコンパイルエラーを回避
- 段階的な移行を可能にする実装パターン

### 移行時の課題と解決

#### 1. Gradle Wrapperの問題

```bash
# Error: Invalid or corrupt jarfile gradle-wrapper.jar
# 解決：正しいwrapper jarを手動で配置
curl -L https://services.gradle.org/distributions/gradle-8.5-bin.zip -o gradle.zip
unzip gradle.zip
cp gradle-8.5/lib/plugins/gradle-wrapper-8.5.jar gradle/wrapper/
```

**学び**：
- ビルドツールの環境構築も重要な技術要素
- Gradle wrapperの構造を理解することで問題解決が迅速に

#### 2. パッケージ構造の維持

新旧APIを共存させるためのパッケージ構造：
```
src/main/java/
├── burp/                    # Legacy API（必須パッケージ名）
│   ├── IBurpExtender.java
│   └── BurpExtender.java
└── com/airis/burp/ai/       # アプリケーションコード
    ├── MontoyaExtension.java # 新API用エントリーポイント
    └── ...
```

**学び**：
- Burp Suiteの制約（burpパッケージ必須）を守りつつ、独自の構造を維持
- 新旧APIの分離で保守性を確保

### Montoya API移行の総括

#### 技術的メリット

1. **型安全性の向上**：byte[]からオブジェクトへ
2. **API設計の改善**：より直感的で理解しやすいメソッド名
3. **依存関係管理**：Maven Centralによる自動化
4. **拡張性**：将来の機能追加が容易な設計

#### 実装上の教訓

1. **段階的移行の重要性**：両APIサポートで安全な移行
2. **ドキュメントの確認**：公式JavaDocの活用が必須
3. **互換性テスト**：新旧両方の環境での動作確認
4. **エラーハンドリング**：API差異によるエラーの適切な処理

#### 今後の展望

Montoya APIは今後のBurp Suite拡張機能開発の標準となるため：
- 新規開発は最初からMontoya APIを使用
- 既存拡張機能も段階的に移行を推奨
- より高度な機能（WebSocket、HTTP/2）の活用が可能

この移行経験により、レガシーシステムの現代化における実践的なアプローチと、APIマイグレーションのベストプラクティスを習得できました。
