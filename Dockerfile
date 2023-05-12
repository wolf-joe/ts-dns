FROM golang:1.20.4-alpine3.18 AS builder

ADD ./go.mod /srv
ADD ./go.sum /srv

WORKDIR /srv
RUN go mod download

ADD ./ /srv
RUN cd cmd && go build -o ts-dns

FROM alpine:3.18.0 AS runner

RUN mkdir /srv/conf && \
    touch /srv/gfwlist.txt

COPY --from=builder  /srv/cmd/ts-dns /srv
COPY ./ts-dns.toml /srv/conf

WORKDIR /srv

CMD ["./ts-dns","-c","/srv/conf/ts-dns.toml"]