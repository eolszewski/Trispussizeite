FROM alpine:latest

RUN apk add --update nodejs nodejs-npm python git make
RUN apk add -U gpgme 

WORKDIR /usr/src/app
COPY . .

RUN npm i
