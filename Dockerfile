FROM oven/bun:1 AS base
WORKDIR /app

# Install Go, Java, and C build tools (gcc/make needed for donut)
RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    default-jdk \
    build-essential \
    git \
    make \
    && rm -rf /var/lib/apt/lists/*

# Build donut shellcode generator from source
RUN git clone --depth 1 https://github.com/thewover/donut.git /tmp/donut-src \
    && make -C /tmp/donut-src \
    && mkdir -p /app/data/tools \
    && cp /tmp/donut-src/donut /app/data/tools/donut \
    && chmod +x /app/data/tools/donut \
    && rm -rf /tmp/donut-src

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

COPY src ./src
COPY public ./public

EXPOSE 7641
CMD ["bun", "run", "src/index.ts"]
