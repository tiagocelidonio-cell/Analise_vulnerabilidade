FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

EXPOSE 5173

# npm install tambem no START: o docker-compose usa um volume anonimo em
# /app/node_modules que PERSISTE entre builds e sombreia o node_modules da
# imagem. Rodar o install no boot garante que novas dependencias (ex.: adicionadas
# via git pull) entrem nesse volume sem precisar remove-lo manualmente.
CMD ["sh", "-c", "npm install && npm run dev"]
