FROM node:20.20.2-alpine3.23

RUN apk add --no-cache make git bash

WORKDIR /app

# Cache dependencies layer
COPY package.json package-lock.json ./
RUN npm ci

# Copy source
COPY . .

CMD ["make", "ci"]
