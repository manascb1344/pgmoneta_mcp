# Local LLM Installation

This guide focuses on installing and configuring a local LLM runtime for pgmoneta MCP.
It is intentionally scoped to local setup and does not cover chat examples or internal
implementation details.

## Scope

This guide covers:

* Installing Ollama, llama.cpp, or vLLM
* Downloading and validating a model
* Configuring the `[llm]` section in `pgmoneta-mcp.conf`

## Selecting a model

When choosing an LLM for **pgmoneta_mcp**, keep these key concepts in mind regardless of which provider you choose:

1. **Instruct vs. Base**: You must use a model fine-tuned for instruction following or chat (usually labeled `Instruct` or `Chat`). Base models are not trained to follow instructions and will fail at tool calling.
2. **Quantization**: Models are compressed ("quantized") to fit into consumer hardware. The default standard is **Q4** (4-bit quantization), which provides an excellent balance of speed, size, and reasoning quality.
3. **Hardware Limits**: The model's listed file size indicates the *minimum* RAM needed simply to load its weights. Actual runtime usage will be 20-30% higher because the runtime allocates memory for context caching and inference buffers.

## Ollama

[Ollama](https://ollama.com) is the recommended provider for running open-source models locally.
It provides a simple CLI and API for downloading, managing, and serving LLM models.

### Install

To install Ollama, follow instructions at [ollama.com/download](https://ollama.com/download).

### Verify installation

```
ollama --version
```

### Start the Ollama server

Ollama runs as a background service. Start it with

```
ollama serve
```

On Linux with systemd, it may already be running as a service after installation.

Verify it is running

```
curl http://localhost:11434/
```

This should print `Ollama is running`.

### Download models

Models must be downloaded before they can be used. This is the only step that requires
network access. Once downloaded, models are cached locally and work fully offline.

* Pull a model

    ```
    ollama pull llama3.1
    ```

* List downloaded models

    ```
    ollama list
    ```

* Test a model

    ```
    ollama run llama3.1 "Hello, what can you do?"
    ```

### Recommended models

The model must support **tool calling** (function calling) to work with pgmoneta MCP tools.

| Model | Size | RAM Needed | Tool Calling | Notes |
| :---- | :--- | :--------- | :----------- | :---- |
| `llama3.1:8b` | ~4.7 GB | ~8 GB | Yes | **Default**. Best balance of capability and size |
| `llama3.2:3b` | ~2.0 GB | ~4 GB | Yes | Lightweight option for limited hardware |
| `qwen2.5:0.5b` | ~0.4 GB | ~1 GB | Yes | Extremely lightweight |
| `qwen2.5:3b` | ~1.9 GB | ~4 GB | Yes | Great balance of speed and capabilities |
| `qwen2.5:7b` | ~4.7 GB | ~8 GB | Yes | Excellent tool calling capabilities |
| `mistral:7b` | ~4.1 GB | ~8 GB | Yes | Strong performance for open-source models |
| `mixtral:8x7b` | ~26.0 GB | ~32 GB | Yes | High quality MoE model |

### Check tool support

You can verify that a model supports tool calling

```
ollama show llama3.1
```

Look for `tools` in the capabilities list. Alternatively, query the API

```
curl -s http://localhost:11434/api/show -d '{"model": "llama3.1"}' | grep capabilities
```

### Configuration

Add an `[llm]` section to your `pgmoneta-mcp.conf`:

```ini
[llm]
provider = ollama
endpoint = http://localhost:11434
model = llama3.1
max_tool_rounds = 10
```

## llama.cpp

[llama.cpp](https://github.com/ggml-org/llama.cpp) provides direct control over hardware for running LLMs locally.

### Install

Download the `llama-server` binary from the [releases page](https://github.com/ggml-org/llama.cpp/releases).

### Download models

Download a `.gguf` model file from a source such as [Hugging Face](https://huggingface.co/). Search for a model name followed by `GGUF` to find the right repository (e.g. `Qwen2.5-7B-Instruct GGUF`).

For **pgmoneta_mcp**, the following specific files are suitable choices:

| Model file | Size | RAM needed | Notes |
| :--------- | :--- | :--------- | :---- |
| `Qwen2.5-7B-Instruct-Q4_K_M.gguf` | ~4.7 GB | ~8 GB | Strong tool calling accuracy |
| `Qwen2.5-3B-Instruct-Q4_K_M.gguf` | ~1.9 GB | ~4 GB | Lower hardware requirement, some accuracy trade-off |
| `Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf` | ~4.7 GB | ~8 GB | Widely used, good general reasoning |

### Start the server

```
llama-server \
  --model models/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf \
  --port 8080 \
  --ctx-size 8192
```

Verify it is running:

```
curl http://localhost:8080/health
```

### Configuration

Add an `[llm]` section to your `pgmoneta-mcp.conf`:

```ini
[llm]
provider = llama.cpp
endpoint = http://localhost:8080
model = Meta-Llama-3.1-8B-Instruct-Q4_K_M
max_tool_rounds = 10
```

## vLLM

[vLLM](https://github.com/vllm-project/vllm) is a high-throughput and memory-efficient engine for LLMs that natively exposes an OpenAI-compatible API.

### Install

Install vLLM via pip (a virtual environment is recommended):

```
pip install vllm
```

### Start the server

vLLM automatically downloads standard Safetensor models from Hugging Face:

```
python -m vllm.entrypoints.openai.api_server \
  --model ibm-granite/granite-3.0-8b-instruct \
  --port 8000
```

Verify it is running:

```
curl http://localhost:8000/v1/models
```

### Configuration

Add an `[llm]` section to your `pgmoneta-mcp.conf`:

```ini
[llm]
provider = vllm
endpoint = http://localhost:8000
model = ibm-granite/granite-3.0-8b-instruct
max_tool_rounds = 10
```

### Configuration properties

| Property | Default | Required | Description |
| :------- | :------ | :------- | :---------- |
| provider |  | Yes | The LLM provider backend (`ollama`, `llama.cpp` or `vllm`) |
| endpoint |  | Yes | The URL of the LLM inference server |
| model |  | Yes | The model name to use for inference |
| max_tool_rounds | 10 | No | Maximum tool-calling iterations per user prompt |

### Quick verification

1. Confirm your runtime is running:

    For Ollama:
    ```
    curl http://localhost:11434/
    ```

    For llama.cpp:
    ```
    curl http://localhost:8080/health
    ```

    For vLLM:
    ```
    curl http://localhost:8000/v1/models
    ```

2. Start pgmoneta MCP with your config file:

```
pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

3. From your MCP client, ask for backup information to verify end-to-end setup.
