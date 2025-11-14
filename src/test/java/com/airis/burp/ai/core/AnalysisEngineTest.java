package com.airis.burp.ai.core;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.llm.AnthropicClient;
import com.airis.burp.ai.llm.OpenAIClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class AnalysisEngineTest {

  @Mock private MontoyaApi montoyaApi;
  @Mock private Logging logging;

  private static final String SAMPLE_REQUEST =
      "GET / HTTP/1.1\r\n"
          + "Host: example.com\r\n"
          + "Accept-Language: en-US,en;q=0.9\r\n"
          + "Upgrade-Insecure-Requests: 1\r\n"
          + "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n"
          + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
          + "Sec-Ch-Ua: \"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"140\"\r\n"
          + "Sec-Ch-Ua-Mobile: ?0\r\n"
          + "Sec-Ch-Ua-Platform: \"Linux\"\r\n"
          + "Sec-Fetch-Site: none\r\n"
          + "Sec-Fetch-Mode: navigate\r\n"
          + "Sec-Fetch-User: ?1\r\n"
          + "Sec-Fetch-Dest: document\r\n"
          + "Accept-Encoding: gzip, deflate, br\r\n"
          + "Priority: u=0, i\r\n"
          + "Connection: keep-alive\r\n"
          + "\r\n";

  private static final String SAMPLE_RESPONSE =
      "HTTP/2 200 OK\r\n"
          + "Accept-Ranges: bytes\r\n"
          + "Content-Type: text/html\r\n"
          + "Etag: \"84238dfc8092e5d9c0dac8ef93371a07:1736799080.121134\"\r\n"
          + "Last-Modified: Mon, 13 Jan 2025 20:11:20 GMT\r\n"
          + "Vary: Accept-Encoding\r\n"
          + "Cache-Control: max-age=86000\r\n"
          + "Date: Thu, 18 Sep 2025 05:34:42 GMT\r\n"
          + "Content-Length: 1256\r\n"
          + "Alt-Svc: h3=\":443\"; ma=93600\r\n"
          + "\r\n"
          + "<!doctype html>\n"
          + "<html>\n"
          + "<head>\n"
          + "    <title>Example Domain</title>\n"
          + "\n"
          + "    <meta charset=\"utf-8\" />\n"
          + "    <meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" />\n"
          + "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n"
          + "    <style type=\"text/css\">\n"
          + "    body {\n"
          + "        background-color: #f0f0f2;\n"
          + "        margin: 0;\n"
          + "        padding: 0;\n"
          + "        font-family: -apple-system, system-ui, BlinkMacSystemFont, \"Segoe UI\", \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\n"
          + "        \n"
          + "    }\n"
          + "    div {\n"
          + "        width: 600px;\n"
          + "        margin: 5em auto;\n"
          + "        padding: 2em;\n"
          + "        background-color: #fdfdff;\n"
          + "        border-radius: 0.5em;\n"
          + "        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);\n"
          + "    }\n"
          + "    a:link, a:visited {\n"
          + "        color: #38488f;\n"
          + "        text-decoration: none;\n"
          + "    }\n"
          + "    @media (max-width: 700px) {\n"
          + "        div {\n"
          + "            margin: 0 auto;\n"
          + "            width: auto;\n"
          + "        }\n"
          + "    }\n"
          + "    </style>    \n"
          + "</head>\n"
          + "\n"
          + "<body>\n"
          + "<div>\n"
          + "    <h1>Example Domain</h1>\n"
          + "    <p>This domain is for use in illustrative examples in documents. You may use this\n"
          + "    domain in literature without prior coordination or asking for permission.</p>\n"
          + "    <p><a href=\"https://www.iana.org/domains/example\">More information...</a></p>\n"
          + "</div>\n"
          + "</body>\n"
          + "</html>";

  @Test
  void OpenAIAnalysisShouldReturnExpectedResult() {
    // Arrange
    ConfigModel openaiConfig =
        new ConfigModel(
            "openai",
            "https://api.openai.com/v1/chat/completions",
            "test-api-key",
            "You are a security analyst. Analyze the following HTTP request and response for security vulnerabilities, potential issues, and provide recommendations. Focus on common web application security issues like injection attacks, authentication bypasses, authorization issues, and data exposure.");
    java.util.concurrent.ExecutorService executorService =
        java.util.concurrent.Executors.newFixedThreadPool(1);
    AnalysisEngine sut =
        new AnalysisEngine(() -> openaiConfig, logging, montoyaApi, executorService);

    // Expected JSON response from OpenAI API
    String mockApiResponse =
        "{\n"
            + "  \"id\": \"chatcmpl-CHmWkRawvFk2MerT7GgfXrvENZB9z\",\n"
            + "  \"object\": \"chat.completion\",\n"
            + "  \"created\": 1758354150,\n"
            + "  \"model\": \"gpt-4o-mini-2024-07-18\",\n"
            + "  \"choices\": [\n"
            + "    {\n"
            + "      \"index\": 0,\n"
            + "      \"message\": {\n"
            + "        \"role\": \"assistant\",\n"
            + "        \"content\": \"### Security Analysis of the Provided HTTP Request and Response\\n\\n#### 1. Potential Vulnerabilities\\n\\n- **SQL Injection**: The provided request is a simple GET request to the root path (`/`). There are no parameters or query strings that could be exploited for SQL injection in this specific request. However, if the application were to accept user input (e.g., through query parameters), it would be crucial to ensure that all inputs are properly sanitized and parameterized to prevent SQL injection attacks.\\n\\n- **Cross-Site Scripting (XSS)**: The response body does not contain any user-generated content, which reduces the risk of XSS. However, if the application were to render user input without proper escaping or sanitization, it could be vulnerable to XSS attacks. Always ensure that any dynamic content is properly encoded before being rendered in the browser.\\n\\n- **Cross-Site Request Forgery (CSRF)**: The request does not include any authentication tokens or session identifiers, which could indicate a lack of CSRF protection. If this application allows state-changing operations (like POST requests), it should implement CSRF tokens to ensure that requests are legitimate.\\n\\n#### 2. Authentication and Authorization Issues\\n\\n- **Authentication**: The request does not appear to include any authentication headers or tokens, which may indicate that the application does not require authentication for accessing the root path. If sensitive information or functionalities are accessible without authentication, this could be a significant security risk.\\n\\n- **Authorization**: Since the request is a simple GET to the root path, there are no authorization checks visible. If the application has areas that require user roles or permissions, it should enforce proper authorization checks to ensure that users can only access resources they are permitted to.\\n\\n#### 3. Input Validation Problems\\n\\n- **Input Validation**: The request does not contain any user input, so input validation issues are not present in this specific instance. However, it is essential to validate and sanitize all user inputs throughout the application to prevent injection attacks and ensure data integrity.\\n\\n#### 4. Information Disclosure Risks\\n\\n- **Information Exposure**: The response does not disclose sensitive information, and the content appears to be a generic example page. However, it is crucial to ensure that error messages, stack traces, or any debug information are not exposed to users, as they can provide attackers with insights into the applicationâs inner workings.\\n\\n- **HTTP Headers**: The request headers include `Sec-Ch-Ua` and `Sec-Fetch-*` headers, which are part of the Client Hints and Fetch Metadata specifications. While these headers do not pose a direct risk, it is essential to ensure that the application does not rely solely on them for security decisions, as they can be manipulated.\\n\\n#### 5. Other Security Concerns\\n\\n- **Secure Communication**: The response does not indicate whether the request was made over HTTPS. If the application is not served over HTTPS, it is susceptible to man-in-the-middle attacks, where an attacker could intercept and manipulate the data being transmitted.\\n\\n- **Content Security Policy (CSP)**: The response does not include a Content Security Policy header. Implementing a CSP can help mitigate XSS risks by controlling the sources from which content can be loaded.\\n\\n- **HTTP Security Headers**: The response lacks several important security headers, such as:\\n  - `X-Content-Type-Options: nosniff` to prevent MIME type sniffing.\\n  - `X-Frame-Options` or `Content-Security-Policy` to prevent clickjacking.\\n  - `Strict-Transport-Security` to enforce HTTPS.\\n\\n### Recommendations\\n\\n1. **Implement Input Validation**: Ensure all user inputs are validated and sanitized to prevent injection attacks.\\n\\n2. **Use HTTPS**: Always serve the application over HTTPS to protect data in transit.\\n\\n3. **Implement Authentication and Authorization**: Ensure that sensitive endpoints require proper authentication and that authorization checks are in place.\\n\\n4. **Add Security Headers**: Implement necessary HTTP security headers to enhance the security posture of the application.\\n\\n5. **Implement CSRF Protection**: Use CSRF tokens for state-changing requests to prevent unauthorized actions.\\n\\n6. **Monitor and Log**: Implement logging and monitoring to detect and respond to suspicious activities.\\n\\n7. **Regular Security Audits**: Conduct regular security assessments and penetration testing to identify and remediate vulnerabilities proactively. \\n\\nBy addressing these areas, the application can significantly improve its security posture and reduce the risk of common web application vulnerabilities.\",\n"
            + "        \"refusal\": null,\n"
            + "        \"annotations\": []\n"
            + "      },\n"
            + "      \"logprobs\": null,\n"
            + "      \"finish_reason\": \"stop\"\n"
            + "    }\n"
            + "  ],\n"
            + "  \"usage\": {\n"
            + "    \"prompt_tokens\": 772,\n"
            + "    \"completion_tokens\": 904,\n"
            + "    \"total_tokens\": 1676,\n"
            + "    \"prompt_tokens_details\": {\n"
            + "      \"cached_tokens\": 0,\n"
            + "      \"audio_tokens\": 0\n"
            + "    },\n"
            + "    \"completion_tokens_details\": {\n"
            + "      \"reasoning_tokens\": 0,\n"
            + "      \"audio_tokens\": 0,\n"
            + "      \"accepted_prediction_tokens\": 0,\n"
            + "      \"rejected_prediction_tokens\": 0\n"
            + "    }\n"
            + "  },\n"
            + "  \"service_tier\": \"default\",\n"
            + "  \"system_fingerprint\": \"fp_560af6e559\"\n"
            + "}";

    // Create a spy of OpenAIClient and mock the sendHttpRequest method
    OpenAIClient openAIClientSpy = spy(new OpenAIClient(montoyaApi));
    doReturn(mockApiResponse)
        .when(openAIClientSpy)
        .sendHttpRequest(any(ConfigModel.class), anyString());

    // Mock the construction of OpenAIClient to return our spy
    try (MockedConstruction<OpenAIClient> mockedConstruction =
        mockConstruction(
            OpenAIClient.class,
            (mock, context) -> {
              // Configure the mock to delegate to our spy
              doAnswer(
                      invocation ->
                          openAIClientSpy.analyze(
                              invocation.getArgument(0), invocation.getArgument(1)))
                  .when(mock)
                  .analyze(any(ConfigModel.class), any());
              doAnswer(
                      invocation ->
                          openAIClientSpy.sendHttpRequest(
                              invocation.getArgument(0), invocation.getArgument(1)))
                  .when(mock)
                  .sendHttpRequest(any(ConfigModel.class), anyString());
            })) {

      // Act
      String result = sut.analyze(SAMPLE_REQUEST, SAMPLE_RESPONSE);

      // Assert
      assertTrue(
          result.startsWith("### Security Analysis of the Provided HTTP Request and Response"),
          "Result should start with '### Security Analysis of the Provided HTTP Request and Response'");
    }
  }

  @Test
  void AnthropicAnalysisShouldReturnExpectedResult() {
    // Arrange
    ConfigModel anthropicConfig =
        new ConfigModel(
            "anthropic",
            "https://api.anthropic.com/v1/messages",
            "test-api-key",
            "You are a security analyst. Analyze the following HTTP request and response for security vulnerabilities, potential issues, and provide recommendations. Focus on common web application security issues like injection attacks, authentication bypasses, authorization issues, and data exposure.");
    java.util.concurrent.ExecutorService executorService2 =
        java.util.concurrent.Executors.newFixedThreadPool(1);
    AnalysisEngine sut =
        new AnalysisEngine(() -> anthropicConfig, logging, montoyaApi, executorService2);

    // Expected JSON response from Anthropic API
    String mockApiResponse =
        "{\n"
            + "  \"id\": \"msg_01KCM4Q1hhtPK1HoK8rGXeNU\",\n"
            + "  \"type\": \"message\",\n"
            + "  \"role\": \"assistant\",\n"
            + "  \"model\": \"claude-3-5-haiku-20241022\",\n"
            + "  \"content\": [\n"
            + "    {\n"
            + "      \"type\": \"text\",\n"
            + "      \"text\": \"Security Analysis of HTTP Request and Response\\n\\nOverall Assessment: Low Risk / Standard Example Domain Request\\n\\n1. Potential Vulnerabilities\\n- No direct injection vulnerabilities detected\\n- Request is a standard GET request to a static example domain\\n- Response is a static HTML page with no dynamic content\\n- No executable scripts or potentially malicious content observed\\n\\n2. Authentication and Authorization\\n- No authentication mechanism present\\n- Public/unauthenticated page\\n- No sensitive information exposed in the request/response\\n\\n3. Input Validation\\n- No user-controlled input in this request\\n- Static HTML response with no dynamic content generation\\n- No apparent input validation concerns\\n\\n4. Information Disclosure Risks\\nPotential Minor Risks:\\n- User-Agent reveals browser and platform details\\n- Sec-Ch-Ua headers provide browser version information\\n- Recommendation: Consider implementing User-Agent normalization if tracking is sensitive\\n\\n5. Additional Security Observations\\nPositive Security Aspects:\\n- Uses HTTPS (indicated by Upgrade-Insecure-Requests header)\\n- No sensitive data transmitted\\n- Standard, well-formed HTTP headers\\n- Responsive design with media queries\\n- No inline JavaScript detected\\n\\nRecommendations:\\n1. Ensure all production sites have similar security hygiene\\n2. Implement Content Security Policy (CSP) headers\\n3. Use strict User-Agent parsing if needed\\n4. Continue using HTTPS\\n\\nRisk Level: Negligible\\nThis is a standard, publicly accessible example domain with no significant security concerns.\"\n"
            + "    }\n"
            + "  ],\n"
            + "  \"stop_reason\": \"end_turn\",\n"
            + "  \"stop_sequence\": null,\n"
            + "  \"usage\": {\n"
            + "    \"input_tokens\": 950,\n"
            + "    \"cache_creation_input_tokens\": 0,\n"
            + "    \"cache_read_input_tokens\": 0,\n"
            + "    \"cache_creation\": {\n"
            + "      \"ephemeral_5m_input_tokens\": 0,\n"
            + "      \"ephemeral_1h_input_tokens\": 0\n"
            + "    },\n"
            + "    \"output_tokens\": 328,\n"
            + "    \"service_tier\": \"standard\"\n"
            + "  }\n"
            + "}";

    // Create a spy of AnthropicClient and mock the sendHttpRequest method
    AnthropicClient anthropicClientSpy = spy(new AnthropicClient(montoyaApi));
    doReturn(mockApiResponse)
        .when(anthropicClientSpy)
        .sendHttpRequest(any(ConfigModel.class), anyString());

    // Mock the construction of AnthropicClient to return our spy
    try (MockedConstruction<AnthropicClient> mockedConstruction =
        mockConstruction(
            AnthropicClient.class,
            (mock, context) -> {
              // Configure the mock to delegate to our spy
              doAnswer(
                      invocation ->
                          anthropicClientSpy.analyze(
                              invocation.getArgument(0), invocation.getArgument(1)))
                  .when(mock)
                  .analyze(any(ConfigModel.class), any());
              doAnswer(
                      invocation ->
                          anthropicClientSpy.sendHttpRequest(
                              invocation.getArgument(0), invocation.getArgument(1)))
                  .when(mock)
                  .sendHttpRequest(any(ConfigModel.class), anyString());
            })) {

      // Act
      String result = sut.analyze(SAMPLE_REQUEST, SAMPLE_RESPONSE);

      // Assert
      assertTrue(
          result.startsWith("Security Analysis of HTTP Request and Response"),
          "Result should start with 'Security Analysis of HTTP Request and Response'");
    }
  }
}
