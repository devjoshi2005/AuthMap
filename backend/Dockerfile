# Use Python 3.11 slim to ensure maximum compatibility with node2vec and scikit-learn
FROM python:3.11-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
COPY . .

ENV FONT_DEJAVU_REGULAR=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
ENV FONT_DEJAVU_BOLD=/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
