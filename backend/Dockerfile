# Use Python 3.11 slim
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# 1. Install ca-certificates and gnupg first to ensure secure apt operations
# 2. Update apt and install required system dependencies
# 3. Clean up apt lists to reduce image size
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    gnupg \
    curl && \
    echo "deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    echo "deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    fonts-dejavu-core \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get purge -y --auto-remove curl gnupg

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FONT_DEJAVU_REGULAR=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
ENV FONT_DEJAVU_BOLD=/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf

EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]