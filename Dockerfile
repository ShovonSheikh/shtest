FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY bot.py .
COPY README.md .

# Create directory for persistent data if needed
RUN mkdir -p /app/data

# Render uses PORT environment variable, default to 4853 if not set
ENV PORT=4853

# Expose the port (Render will override this with their PORT variable)
EXPOSE $PORT

# Health check (optional on Render as they have their own health checks)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Run the bot with unbuffered output for better logging
CMD ["python", "-u", "bot.py"]
