FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .

FROM node:20

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH="/usr/bin/google-chrome-stable"

RUN apt-get update \
    && apt-get install -y wget fonts-liberation libgbm-dev \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list \
    && apt-get update && apt-get -y install google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# see https://peter.sh/experiments/chromium-command-line-switches/
ARG CHROME_SANDBOX_FLAGS="--no-sandbox,--disable-setuid-sandbox"
ARG CHROME_RENDER_FLAGS="--disable-gpu,--disable-dev-shm-usage,--disable-software-rasterizer"
ARG CHROME_ISOLATION_FLAGS="--disable-features=IsolateOrigins,--disable-site-isolation-trials,--disable-features=BlockInsecurePrivateNetworkRequests"
ARG CHROME_STORAGE_FLAGS="--disable-features=ThirdPartyStoragePartitioning,--disable-features=LazyFrameLoading"
ARG CHROME_NET_FLAGS="--disable-background-networking,--disable-default-apps"

ENV BROWSER_FLAGS="${CHROME_SANDBOX_FLAGS},${CHROME_RENDER_FLAGS},${CHROME_ISOLATION_FLAGS},${CHROME_STORAGE_FLAGS},${CHROME_NET_FLAGS}"

RUN groupadd -r app && useradd -r -g app app \
    && mkdir -p /home/app && chown -R app:app /home/app

WORKDIR /app
COPY --from=builder /app /app
RUN chown -R app:app /app

USER app
EXPOSE 3031
CMD ["node", "index.js"]