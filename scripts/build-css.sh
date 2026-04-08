#!/bin/bash
# Build Tailwind CSS for Tier Zero C.O.D.E
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Determine the correct binary name
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    TAILWIND_BIN="$PROJECT_ROOT/tailwindcss.exe"
else
    TAILWIND_BIN="$PROJECT_ROOT/tailwindcss"
fi

INPUT="$PROJECT_ROOT/apps/main/static/main/css/tailwind-input.css"
OUTPUT="$PROJECT_ROOT/apps/main/static/main/css/tailwind-output.css"

if [ "$1" = "--watch" ]; then
    echo "Watching for changes..."
    "$TAILWIND_BIN" -i "$INPUT" -o "$OUTPUT" --watch
elif [ "$1" = "--minify" ]; then
    echo "Building minified CSS..."
    "$TAILWIND_BIN" -i "$INPUT" -o "$OUTPUT" --minify
else
    echo "Building CSS..."
    "$TAILWIND_BIN" -i "$INPUT" -o "$OUTPUT"
fi
