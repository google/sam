FROM node:22-slim

WORKDIR /srv
COPY package.json server.mjs lease-token.mjs ./
RUN npm install

EXPOSE 7780
CMD ["node", "server.mjs"]
