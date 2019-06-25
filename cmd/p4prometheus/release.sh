#!/bin/bash
# Home OS is Mac/Darwin

GOOS=linux GOARCH=amd64 go build -o p4prometheus.linux-amd64
GOOS=windows GOARCH=amd64 go build -o p4prometheus.windows-amd64
go build -o p4prometheus.darwin-amd64

chmod +x p4prometheus*amd64
chmod +w p4prometheus*amd64.gz
rm p4prometheus*amd64.gz
gzip p4prometheus*amd64

