# Container scanning: node:14 is end-of-life
FROM node:14
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "app.js"]
