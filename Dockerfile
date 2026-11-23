FROM golang:1.27.1 AS build

WORKDIR /src

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o /kv-store .

FROM scratch

COPY --from=build /kv-store /kv-store

EXPOSE 8080

ENTRYPOINT ["/kv-store"]
