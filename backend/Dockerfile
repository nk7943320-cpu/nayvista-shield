FROM node:20-bookworm-slim

# Install Python3, pip, and CA certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements in virtualenv or global
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend dependencies
COPY backend/package*.json ./backend/
WORKDIR /app/backend
RUN npm ci

# Copy full source
WORKDIR /app
COPY scanner ./scanner
COPY backend ./backend

WORKDIR /app/backend
RUN npm run build

ENV NODE_ENV=production
ENV PORT=5000
ENV HOST=0.0.0.0
ENV PYTHON_BIN=/opt/venv/bin/python3

EXPOSE 5000

CMD ["node", "dist/index.js"]
