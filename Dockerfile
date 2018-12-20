FROM node:10

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install
RUN npm install -g retire
RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install unzip

COPY . .

EXPOSE 9001

CMD ["npm", "start"]