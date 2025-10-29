FROM node:22-alpine AS development
WORKDIR /app
RUN npm install -g pnpm
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
EXPOSE 7000
CMD [ "sh", "-c", "pnpm db:deploy && pnpm run dev" ]

FROM node:22-alpine AS builder
WORKDIR /app
RUN npm install -g pnpm
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm prisma generate && pnpm run build

FROM node:22-alpine AS production
WORKDIR /app
RUN npm install -g pnpm
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/generated ./generated
ENV NODE_ENV=production
EXPOSE 7000
CMD ["sh", "-c", "pnpm db:deploy && pnpm start"]