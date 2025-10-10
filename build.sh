
set -e  # Exit on error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_NAME="syshardn"
VERSION=$(grep '^version' pyproject.toml | cut -d'"' -f2 || echo "0.1.0")
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

CLEAN=false
BUILD_WHEEL=false
BUILD_EXE=true
BUILD_ALL=false

for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN=true
            ;;
        --wheel)
            BUILD_WHEEL=true
            BUILD_EXE=false
            ;;
        --all)
            BUILD_ALL=true
            BUILD_WHEEL=true
            BUILD_EXE=true
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --clean     Clean build directories before building"
            echo "  --wheel     Build Python wheel only"
            echo "  --all       Build both executable and wheel"
            echo "  --help      Show this help message"
            exit 0
            ;;
    esac
done

if [ "$CLEAN" = true ]; then
    print_section "Cleaning Build Directories"
    echo -e "${YELLOW}Removing build artifacts...${NC}"
    rm -rf build/ dist/ *.spec.bak
    rm -rf src/*.egg-info
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    echo -e "${GREEN}✓ Clean complete${NC}"
fi

print_section "Running Tests"
if command_exists pytest; then
    echo -e "${YELLOW}Running test suite...${NC}"
    if python -m pytest tests/ -v --tb=short; then
        echo -e "${GREEN}✓ All tests passed${NC}"
    else
        echo -e "${RED}✗ Tests failed! Build aborted.${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ pytest not found, skipping tests${NC}"
fi

if [ "$BUILD_EXE" = true ]; then
    print_section "Building Standalone Executable"

    if ! command_exists pyinstaller; then
        echo -e "${YELLOW}Installing PyInstaller...${NC}"
        pip install pyinstaller
    fi
    
    echo -e "${YELLOW}Building with PyInstaller...${NC}"
    pyinstaller syshardn.spec --clean

    if [ -f "dist/$PROJECT_NAME" ]; then
        OUTPUT_NAME="${PROJECT_NAME}-v${VERSION}-${PLATFORM}-${ARCH}"
        mv "dist/$PROJECT_NAME" "dist/$OUTPUT_NAME"
        
        echo ""
        echo -e "${GREEN}✓ Executable built successfully!${NC}"
        echo -e "${GREEN}  Location:${NC} dist/$OUTPUT_NAME"

        SIZE=$(du -h "dist/$OUTPUT_NAME" | cut -f1)
        echo -e "${GREEN}  Size:${NC} $SIZE"

        print_section "Testing Executable"
        echo -e "${YELLOW}Running basic tests...${NC}"
        
        if "./dist/$OUTPUT_NAME" --version >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Version check: OK${NC}"
        else
            echo -e "${YELLOW}⚠ Version check failed (may be normal)${NC}"
        fi
        
        if "./dist/$OUTPUT_NAME" --help >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Help command: OK${NC}"
        fi
        
        if "./dist/$OUTPUT_NAME" list-rules >/dev/null 2>&1; then
            echo -e "${GREEN}✓ List rules: OK${NC}"
        else
            echo -e "${RED}✗ List rules failed${NC}"
        fi
 
        print_section "Creating Distribution Archive"
        echo -e "${YELLOW}Creating archive...${NC}"
        
        cd dist
        tar -czf "${OUTPUT_NAME}.tar.gz" "$OUTPUT_NAME"

        if command_exists sha256sum; then
            sha256sum "${OUTPUT_NAME}.tar.gz" > "${OUTPUT_NAME}.tar.gz.sha256"
            echo -e "${GREEN}✓ Archive created: ${OUTPUT_NAME}.tar.gz${NC}"
            echo -e "${GREEN}✓ Checksum: ${OUTPUT_NAME}.tar.gz.sha256${NC}"
        elif command_exists shasum; then
            shasum -a 256 "${OUTPUT_NAME}.tar.gz" > "${OUTPUT_NAME}.tar.gz.sha256"
            echo -e "${GREEN}✓ Archive created: ${OUTPUT_NAME}.tar.gz${NC}"
            echo -e "${GREEN}✓ Checksum: ${OUTPUT_NAME}.tar.gz.sha256${NC}"
        fi
        
        cd ..
        
    else
        echo -e "${RED}✗ Build failed! Executable not found.${NC}"
        exit 1
    fi
fi

if [ "$BUILD_WHEEL" = true ]; then
    print_section "Building Python Wheel"

    if ! python -c "import build" >/dev/null 2>&1; then
        echo -e "${YELLOW}Installing build tools...${NC}"
        pip install build wheel
    fi
    
    echo -e "${YELLOW}Building wheel package...${NC}"
    python -m build

    WHEEL_FILE=$(ls dist/*.whl 2>/dev/null | head -n1)
    if [ -n "$WHEEL_FILE" ]; then
        echo -e "${GREEN}✓ Wheel built successfully!${NC}"
        echo -e "${GREEN}  Location:${NC} $WHEEL_FILE"

        SIZE=$(du -h "$WHEEL_FILE" | cut -f1)
        echo -e "${GREEN}  Size:${NC} $SIZE"

        if command_exists sha256sum; then
            sha256sum "$WHEEL_FILE" > "${WHEEL_FILE}.sha256"
        elif command_exists shasum; then
            shasum -a 256 "$WHEEL_FILE" > "${WHEEL_FILE}.sha256"
        fi
    else
        echo -e "${RED}✗ Wheel build failed!${NC}"
        exit 1
    fi
fi

print_section "Build Summary"
echo -e "${GREEN}Build completed successfully!${NC}"
echo ""
echo "Distribution files:"
ls -lh dist/ | tail -n +2 | awk '{print "  " $9 " (" $5 ")"}'
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Test the executable: ./dist/${PROJECT_NAME}-v${VERSION}-${PLATFORM}-${ARCH} list-rules"
echo "  2. Transfer to target systems for testing"
echo "  3. Run with sudo/admin privileges for actual checks"
echo ""
echo -e "${YELLOW}Quick test commands:${NC}"
echo "  ./dist/${PROJECT_NAME}-v${VERSION}-${PLATFORM}-${ARCH} --help"
echo "  ./dist/${PROJECT_NAME}-v${VERSION}-${PLATFORM}-${ARCH} list-rules"
echo "  sudo ./dist/${PROJECT_NAME}-v${VERSION}-${PLATFORM}-${ARCH} check --level moderate --dry-run"
echo ""
echo -e "${GREEN}✓ Done!${NC}"
