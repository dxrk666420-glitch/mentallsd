FROM oven/bun:1 AS base
WORKDIR /app

# Install Java, C build tools (gcc/make needed for donut), and curl for Go tarball
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk \
    build-essential \
    git \
    make \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install official Go 1.22 (apt version is too old / missing Windows cross-compile support)
RUN curl -fsSL https://go.dev/dl/go1.22.4.linux-amd64.tar.gz \
    | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

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
