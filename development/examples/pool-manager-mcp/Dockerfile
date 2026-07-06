FROM node:22-slim

WORKDIR /srv
COPY package.json server.mjs ./
RUN npm install

EXPOSE 7780
CMD ["node", "server.mjs"]
