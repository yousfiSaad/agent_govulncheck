# Stage 1: Build govulncheck
FROM golang:1.22-alpine AS govulncheck-builder
RUN apk add --no-cache git
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# Stage 2: Python base
FROM python:3.11-alpine as base

# Stage 3: Build Python dependencies
FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --upgrade pip setuptools wheel && \
    pip install --prefix=/install -r /requirements.txt --no-cache-dir

# Stage 4: Runtime
FROM base
# Install git for Go module operations
RUN apk add --no-cache git
# Copy Go toolchain from builder stage to ensure version compatibility
COPY --from=govulncheck-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
COPY --from=builder /install /usr/local
COPY --from=govulncheck-builder /go/bin/govulncheck /usr/local/bin/govulncheck
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY oxo.yaml /app/oxo.yaml
WORKDIR /app
CMD ["python3", "-m", "agent"]