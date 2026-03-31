FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml uv.lock* README.md ./
COPY mpp_scanner/ mpp_scanner/
COPY cli/ cli/

# Install dependencies
RUN uv sync --frozen --no-dev 2>/dev/null || uv sync --no-dev

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "mpp_scanner.service.app:app", "--host", "0.0.0.0", "--port", "8000"]
