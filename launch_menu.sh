#!/usr/bin/env bash
# EraseCure Interactive TUI Launcher for SIH Demo
# Sanitized against NBSP (\xC2\xA0) corruption, path drift, and silent exit-code swallowing.

# Enforce strict POSIX error handling and pipe failures
set -euo pipefail

# Resolve script directory dynamically to prevent context drift
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
BINARY="${SCRIPT_DIR}/build/bin/erasecure"

# Automated Sandbox Fallback: Ensure test images exist relative to project root if missing
ensure_sandbox() {
    local target="$1"
    if [ ! -f "$target" ]; then
        echo "[*] Sandbox target '$target' missing. Generating mock test image via dd..."
        dd if=/dev/zero of="$target" bs=1M count=10 status=none
        echo "[+] Successfully created sandbox target: $target"
    fi
}

if [ ! -f "$BINARY" ]; then
    echo "[-] Error: erasecure binary not found at $BINARY. Please run cmake/make first." >&2
    exit 1
fi

while true; do
    clear
    echo "╔══════════════════════════════════════════════════╗"
    echo "║      EraseCure v0.1.0-dev — SIH Live Demo TUI      ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo ""
    echo "  1) List Detected Devices / Status"
    echo "  2) Run Zero-Fill Wipe Test (Fast)"
    echo "  3) Run Multi-Pass Random Overwrite & Verify"
    echo "  4) View Audit Log Output Sample"
    echo "  5) Exit"
    echo ""
    read -p "Select an option [1-5]: " choice

    case $choice in
        1)
            echo ""
            echo "[*] Enumerating devices..."
            if ! "$BINARY" --list-devices; then
                echo "[-] Error: Device enumeration failed." >&2
            fi
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        2)
            echo ""
            read -p "Enter target image path (default: ./zero_test.img): " img_path
            img_path=${img_path:-./zero_test.img}
            read -p "Enter number of passes (default: 1): " passes
            passes=${passes:-1}
            
            ensure_sandbox "$img_path"

            echo ""
            echo "[*] Executing zero wipe on $img_path..."
            if ! "$BINARY" --test-image "$img_path" --block-erase zero --passes "$passes" --verify; then
                echo "[-] Error: Zero-fill wipe execution failed or returned non-zero exit code." >&2
            fi
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        3)
            echo ""
            read -p "Enter target image path (default: ./multi_test.img): " img_path
            img_path=${img_path:-./multi_test.img}
            read -p "Enter number of passes (default: 3): " passes
            passes=${passes:-3}
            
            ensure_sandbox "$img_path"

            echo ""
            echo "[*] Executing multi-pass random secure wipe with full verify..."
            if ! "$BINARY" --test-image "$img_path" --block-erase random --passes "$passes" --verify-full; then
                echo "[-] Error: Multi-pass secure wipe failed or encountered verification errors." >&2
            fi
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        4)
            echo ""
            echo "[*] Generating compliance audit record sample..."
            echo "--------------------------------------------------"
            echo "Timestamp      : $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
            echo "Tool Version   : EraseCure v0.1.0-dev (POSIX C17)"
            echo "Operation      : Secure Block Overwrite & Verification"
            echo "Algorithm      : NIST SP 800-88 Rev. 1 Clears Spec"
            echo "Status         : SUCCESS (0 Verification Mismatches)"
            echo "--------------------------------------------------"
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        5)
            echo "Exiting EraseCure TUI. Good luck with the SIH pitch!"
            exit 0
            ;;
        *)
            echo "Invalid option. Try again."
            sleep 1
            ;;
    esac
done
