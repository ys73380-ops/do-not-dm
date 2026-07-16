FROM python:3.11-slim

WORKDIR /app

# System deps (kept minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy bot code
COPY bot.py .

# Env vars are supplied at runtime (Railway/Back4App/Northflank "Variables" tab)
# BOT_TOKEN=...
# SUPABASE_URL=...
# SUPABASE_KEY=...
# GROQ_API_KEY=...
# GROQ_MODEL=...

CMD ["python", "bot.py"]
