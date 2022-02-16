FROM alpine:3.13.5
RUN apk add --no-cache linux-headers make alpine-sdk clang llvm libbpf-dev libc-dev iproute2 go bsd-compat-headers
RUN go get github.com/dropbox/goebpf
COPY . /app/sock
WORKDIR /app/sock
RUN make
# RUN go build main.go
# RUN ls -lash bpf
ENTRYPOINT ["./main"]