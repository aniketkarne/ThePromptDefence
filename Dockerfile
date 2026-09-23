FROM python:3.10-slim

LABEL org.opencontainers.image.title="ThePromptDefence"
LABEL org.opencontainers.image.description="A Local-First, Zero-Cost Prompt Injection Detection Server for MCP"

WORKDIR /app

COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src

# Create log directory
RUN mkdir -p /root/.shield-mcp/logs

# Install dependencies and the package
RUN pip install --no-cache-dir .

# Pre-cache the DeBERTa model so first container run doesn't download ~400MB.
# Uses HF_HOME so the cache lives in the standard HuggingFace location.
# Calls warm_up() instead of MLDetector() because MLDetector() is now a no-op
# (load is deferred to first .check() call — see src/shield_mcp/detectors/ml_models.py).
RUN python -c "\
    import os; \
    os.environ['HF_HOME'] = '/root/.cache/huggingface'; \
    os.makedirs('/root/.cache/huggingface', exist_ok=True); \
    from shield_mcp.detectors.ml_models import MLDetector; \
    MLDetector().warm_up() \
    "

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV HF_HOME="/root/.cache/huggingface"

# Run the server
CMD ["python", "-m", "shield_mcp.server"]
