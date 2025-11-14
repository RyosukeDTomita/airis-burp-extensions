# AIris: Artificial Intelligence Request Insight System

![mit license](https://img.shields.io/github/license/RyosukeDTomita/airis)
[![Test](https://github.com/RyosukeDTomita/airis-burp-extensions/actions/workflows/test-coverage.yml/badge.svg)](https://github.com/RyosukeDTomita/airis-burp-extensions/actions/workflows/test-coverage.yml)
[![codecov](https://codecov.io/gh/RyosukeDTomita/airis-burp-extensions/branch/main/graph/badge.svg)](https://codecov.io/gh/RyosukeDTomita/airis-burp-extensions)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/RyosukeDTomita/airis-burp-extensions/badge)](https://securityscorecards.dev/viewer/?uri=github.com/RyosukeDTomita/airis-burp-extensions)
[![Scorecard supply-chain security](https://github.com/RyosukeDTomita/airis-burp-extensions/actions/workflows/scorecard.yml/badge.svg)](https://github.com/RyosukeDTomita/airis-burp-extensions/actions/workflows/scorecard.yml)
[![CodeQL](https://github.com/RyosukeDTomita/airis-burp-extensions/actions/workflows/codeql.yml/badge.svg)](https://github.com/RyosukeDTomita/airis-burp-extensions/actions/workflows/codeql.yml)

<img src="./assets/airis_icon.png" width="33%" height="33%" alt="AIris">

## INDEX

- [ABOUT](#about)
- [HOW TO USE](#how-to-use)
- [ENVIRONMENT](#environment)
- [PREPARING](#preparing)
- [For Developers](#for-developers)

---

## ABOUT

This is an [Burp Suite](https://portswigger.net/burp) extension that allows you to **LLM custom API key and API endpoint**, and send the selected request and response from within Burp Suite as context for analysis by an LLM.

### Why AIris?

- [Burp AI](https://portswigger.net/burp/ai) is not supported in the free version of Burp Suite.
- Some companies only allow the use of organization-managed AI services, such as [Azure OpenAI](https://learn.microsoft.com/ja-jp/azure/ai-foundry/openai/overview), [Amazon Bedrock](https://aws.amazon.com/jp/bedrock/).

### Supported LLMs

- OpenAI
- Azure OpenAI
- Anthropic Claude
- (Planned) Amazon Bedrock Claude

---

## HOW TO USE

1. Open Burp Suite and add .jar file.
    ![extensions](./assets/add_extensions.png)
2. Move to `AIris Config` tab and put your API key and endpoint. Don't forget to push Save button.
    ![api-key](./assets/settings.png)
3. Select Burp Suite's HTTP history tab, right-click on a request or response, and send to `AIris Analysis` tab then you can write your prompt.
    ![right_click_menu](./assets/right_click_menu.png)
    ![your prompt](./assets/your_prompt.png)
4. Move to `AIris Analysis` tab right click on the request and push `Send Request` button. Then you can see the analysis result from LLM.
    ![response](./assets/send_request.png)
    ![result](./assets/result.png)

### Using Azure Open AI

Replacing the endpoint will make it work.
Include the model name and version as shown below.

```
https://<your-resource-name>.openai.azure.com/openai/deployments/<deployment-name>/chat/completions?api-version=<api-version>
e.g. https://sigma-oai-westus.openai.azure.com/openai/deployments/gpt-40-mini/chat/completions?api-version=2024-02-15-preview
```

### Using Amazon Bedrock(Claude)

I'll test it soon.
Looking for volunteers to help verify functionality.

---

## ENVIRONMENT

This project is just Vibe Coding right now.
I'm improveing it little by little.

- Docker Image: gradle:9.0.0-jdk21-noble
- Java: 21
  - montoya-api: 2025.7
- Gradle: 9.0.0

---

## PREPARING

```shell
cd airis
./build.sh
```

---

## For Developers

### Format code

```shell
cd airis
./gradlew fmt
```

### Test code

```shell
cd airis
./gradlew test --tests <ClassName of Test.java>
# print debug
./gradlew test --tests <ClassName of Test.java> --info
# all test
./gradlew test
```
