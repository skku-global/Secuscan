# ==============================================================================
# SECUSCAN BACKEND DOCKERFILE — Google Cloud Run Containerization
#
# WHY THIS DOCKERFILE EXISTS:
# Google Cloud Run is a serverless container platform with specific runtime contracts:
#   1. DYNAMIC PORT: Cloud Run assigns a port dynamically via the $PORT environment
#      variable (typically 8080, but variable). The application MUST listen on this
#      port rather than a hardcoded port.
#   2. ALL INTERFACES: The server must bind to 0.0.0.0, not 127.0.0.1 / localhost.
#   3. LOG STREAMING: PYTHONUNBUFFERED=1 ensures logs are immediately flushed to
#      Cloud Logging without stream buffering delays.
#   4. GRACEFUL TERMINATION: Using `exec uvicorn` allows uvicorn to run as PID 1
#      and directly intercept SIGTERM signals sent by Cloud Run during autoscaling,
#      enabling graceful in-flight request completion.
#   5. LEAST PRIVILEGE: Runs as a non-root user (`appuser`) for defense in depth.
# ==============================================================================

# Use official lightweight Python image
FROM python:3.12-slim

# Prevent Python from writing .pyc files and force unbuffered logging for Cloud Logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# Working directory inside the container
WORKDIR /app

# Layer caching: copy and install dependencies before copying application code
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code into container
COPY . .

# Security best practice: execute as non-root user
RUN adduser --disabled-password --gecos "" --no-create-home appuser && \
    chown -R appuser:appuser /app

USER appuser

# Metadata documentation: Cloud Run defaults to 8080
EXPOSE 8080

# Launch uvicorn listening on 0.0.0.0 with the port from $PORT (defaulting to 8080).
# `exec` replaces the shell process so uvicorn receives SIGTERM directly.
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
