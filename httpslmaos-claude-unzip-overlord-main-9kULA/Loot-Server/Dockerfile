FROM oven/bun:1
WORKDIR /app

COPY package.json ./
RUN bun install

COPY src/ ./src/

EXPOSE 5175
ENV PORT=5175
ENV HOST=0.0.0.0

CMD ["bun", "src/index.ts"]
