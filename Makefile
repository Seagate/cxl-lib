# Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates

APP_NAME := cxl-util

help:
	@echo ""
	@echo "-----------------------------------------------------------------------------------"
	@echo "make clean        - remove all"
	@echo "make local        - build a local executable"
	@echo "make rebuild      - rebuild a local executable"
	@echo "make fmt          - Run gofmt"	
	@echo ""

clean:
	@echo "Clean up..."
	go clean
	rm -f $(APP_NAME)

local: clean
	@echo "Build local executable..."
	go build -o $(APP_NAME) -ldflags "-X main.buildTime=`date -u '+%Y-%m-%dT%H:%M:%S'`" ./cmd/$(APP_NAME)/main.go
	ls -lh $(APP_NAME)

fmt:
	@echo "Format check"
	gofmt -s -w .

rebuild:
	@echo "Rebuild local executable..."
	go build -a -o $(APP_NAME) -ldflags "-X main.buildTime=`date -u '+%Y-%m-%dT%H:%M:%S'`" ./cmd/$(APP_NAME)/main.go
	ls -lh $(APP_NAME)
