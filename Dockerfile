FROM golang:1.20.6-alpine3.18 AS BuildStage

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o /app/main .

FROM alpine:latest

WORKDIR /app

COPY --from=BuildStage /app/main /app/main

ENV APP_ID=app
#app url in your internal network
ENV FORWARD_URL=http://192.168.0.2:25000
ENV OPENID_CONFIG_URL=https://xxxxx/webman/sso/.well-known/openid-configuration
ENV REDIRECT_URL=https://yourproxyurl

EXPOSE 10000

ENTRYPOINT ["/app/main"]