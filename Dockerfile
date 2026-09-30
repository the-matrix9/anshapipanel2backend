FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

RUN mkdir -p /app/data

EXPOSE 4000

CMD ["sh", "-c", "node src/db/seed.js && node src/server.js"]
