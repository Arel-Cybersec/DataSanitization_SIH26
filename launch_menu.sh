#!/bin/bash

# EraseCure Interactive TUI Launcher for SIH Demo
# Ensures a foolproof, zero-error live demonstration for judges.

BINARY="./build/bin/erasecure"

if [ ! -f "$BINARY" ]; then
    echo "[-] Error: erasecure binary not found at $BINARY. Please run cmake/make first."
    exit 1
fi

while true; do
    clear
    echo "╔══════════════════════════════════════════════════╗"
    echo "║     EraseCure v0.1.0-dev — SIH Live Demo TUI     ║"
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
            $BINARY --list-devices
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        2)
            echo ""
            read -p "Enter target image path (default: ../zero_test.img): " img_path
            img_path=${img_path:-../zero_test.img}
            read -p "Enter number of passes (default: 1): " passes
            passes=${passes:-1}
            
            echo ""
            echo "[*] Executing zero wipe on $img_path..."
            $BINARY --test-image "$img_path" --block-erase zero --passes "$passes" --verify
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        3)
            echo ""
            read -p "Enter target image path (default: ../multi_test.img): " img_path
            img_path=${img_path:-../multi_test.img}
            read -p "Enter number of passes (default: 3): " passes
            passes=${passes:-3}
            
            echo ""
            echo "[*] Executing multi-pass random secure wipe with full verify..."
            $BINARY --test-image "$img_path" --block-erase random --passes "$passes" --verify-full
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
