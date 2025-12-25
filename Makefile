# -----------------------------------------------------------------------------
# 설정 변수
# -----------------------------------------------------------------------------
BINARY_NAME := HWPScanner.exe
DIST_DIR := bin
MAIN_FILE := ./cmd/project_apollo/main.go
CLI_BINARY_NAME := HWPScanner_CLI.exe

# -----------------------------------------------------------------------------
# 크로스 컴파일러 설정 (Zig)
# -----------------------------------------------------------------------------
# Windows (x86_64) 타겟 설정
ZIG_CC_WIN := zig cc -target x86_64-windows-gnu
ZIG_CXX_WIN := zig c++ -target x86_64-windows-gnu

# -----------------------------------------------------------------------------
# 빌드 명령어
# -----------------------------------------------------------------------------
.PHONY: all windows clean cli cli-local

all: windows cli cli-local

# Windows용 빌드 타겟
windows:
	@echo "🪟 Building for Windows (amd64) using Zig..."
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 \
	GOOS=windows \
	GOARCH=amd64 \
	CC="$(ZIG_CC_WIN)" \
	CXX="$(ZIG_CXX_WIN)" \
	go build -ldflags "-H=windowsgui -s -w" \
	-o $(DIST_DIR)/$(BINARY_NAME) \
	$(MAIN_FILE)
	@echo "✅ Build Complete: $(DIST_DIR)/$(BINARY_NAME)"

# CLI: local build (host)
cli-local:
	@echo "🖥️ Building CLI for host (no cross-compile)..."
	@mkdir -p $(DIST_DIR)
	go build -tags cli -o $(DIST_DIR)/project_apollo_cli ./cmd/project_apollo
	@echo "✅ CLI Build Complete: $(DIST_DIR)/project_apollo_cli"

# CLI: Windows cross-build (Zig)
cli:
	@echo "🪟 Building CLI for Windows (amd64) using Zig..."
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 \
	GOOS=windows \
	GOARCH=amd64 \
	CC="$(ZIG_CC_WIN)" \
	CXX="$(ZIG_CXX_WIN)" \
	go build -tags cli -ldflags "-s -w" \
	-o $(DIST_DIR)/$(CLI_BINARY_NAME) \
	$(MAIN_FILE)
	@echo "✅ CLI Build Complete: $(DIST_DIR)/$(CLI_BINARY_NAME)"

# 청소
clean:
	@echo "🧹 Cleaning..."
	rm -rf $(DIST_DIR)