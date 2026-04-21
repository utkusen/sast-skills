FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY bin ./bin
COPY src ./src
COPY sast-files ./sast-files
RUN npm link

WORKDIR /work
ENTRYPOINT ["sast-skills"]
