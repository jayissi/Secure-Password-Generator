#!/bin/bash
# Integration tests for Secure Password Generator
#
# This script can be run directly or sourced.
# When sourced, it preserves the original shell state.

# Detect if script is being sourced
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    _IS_SOURCED=1
else
    _IS_SOURCED=0
fi

# Save original shell options BEFORE any changes
_ORIGINAL_SHELLOPTS="${-}"
_ORIGINAL_ERREXIT=""

# Check if errexit was set
if [[ "${_ORIGINAL_SHELLOPTS}" == *e* ]]; then
    _ORIGINAL_ERREXIT="set"
else
    _ORIGINAL_ERREXIT="unset"
fi

# Function to restore original shell state
restore_shell_state() {
    if [[ "${_ORIGINAL_ERREXIT}" == "set" ]]; then
        set -e
    else
        set +e
    fi
}

# Function to exit/return appropriately
script_exit() {
    local exit_code=$1
    # Explicitly restore state before exiting/returning
    restore_shell_state
    # Remove trap to avoid double execution
    trap - EXIT
    if [[ "${_IS_SOURCED}" -eq 1 ]]; then
        # When sourced, use return (but restore state first)
        return $exit_code 2>/dev/null || exit $exit_code
    else
        exit $exit_code
    fi
}

# Set error handling for this script execution
set -e

# Trap to restore shell state on exit (when sourced or executed)
# This is a safety net in case script_exit is not called
trap 'restore_shell_state' EXIT

echo "=========================================="
echo "Testing Secure Password Generator"
echo "=========================================="

# ============================================
# BASIC FUNCTIONALITY TESTS
# ============================================

# Test 1: Basic password generation
echo -e "\n[TEST 1] Basic password generation"
python3 password_generator.py -F -L 16 -n || { echo "[FAIL] Test 1 failed"; script_exit 1; }

# Test 2: Password with metadata (label, category, tags)
echo -e "\n[TEST 2] Password with metadata (label, category, tags)"
python3 password_generator.py -F -L 16 --label "Gmail Account" --category "Email" --tags "work,important" || { echo "[FAIL] Test 2 failed"; script_exit 2; }

# Test 3: Multiple passwords with different metadata
echo -e "\n[TEST 3] Multiple passwords with different metadata"
python3 password_generator.py -F -L 12 --label "Bank Account" --category "Banking" --tags "critical,2fa" -c 2 || { echo "[FAIL] Test 3 failed"; script_exit 3; }

# Test 4: Password with custom passphrase
echo -e "\n[TEST 4] Custom passphrase with metadata"
python3 password_generator.py -P "MySecurePass123!" --label "Custom Pass" --category "Personal" --tags "manual" || { echo "[FAIL] Test 4 failed"; script_exit 4; }

# ============================================
# CHARACTER TYPE TESTS
# ============================================

# Test 5: Upper case only
echo -e "\n[TEST 5] Upper case only"
python3 password_generator.py -u -L 10 -n || { echo "[FAIL] Test 5 failed"; script_exit 5; }

# Test 6: Lower case only
echo -e "\n[TEST 6] Lower case only"
python3 password_generator.py -l -L 10 -n || { echo "[FAIL] Test 6 failed"; script_exit 6; }

# Test 7: Digits only
echo -e "\n[TEST 7] Digits only"
python3 password_generator.py -d -L 10 -n || { echo "[FAIL] Test 7 failed"; script_exit 7; }

# Test 8: Symbols only
echo -e "\n[TEST 8] Symbols only"
python3 password_generator.py -s -L 10 -n || { echo "[FAIL] Test 8 failed"; script_exit 8; }

# Test 9: Custom symbols
echo -e "\n[TEST 9] Custom symbols"
python3 password_generator.py -a '@#$%*' -L 10 -n || { echo "[FAIL] Test 9 failed"; script_exit 9; }

# Test 10: Blank character
echo -e "\n[TEST 10] Blank character included"
python3 password_generator.py -F -b -L 16 -n || { echo "[FAIL] Test 10 failed"; script_exit 10; }

# ============================================
# ADVANCED OPTION TESTS
# ============================================

# Test 11: Exclude similar characters
echo -e "\n[TEST 11] Exclude similar characters"
python3 password_generator.py -F -e -L 16 -n || { echo "[FAIL] Test 11 failed"; script_exit 11; }

# Test 12: No repeats
echo -e "\n[TEST 12] No consecutive repeats"
python3 password_generator.py -F -r -L 16 -n || { echo "[FAIL] Test 12 failed"; script_exit 12; }

# Test 13: Minimum characters per type
echo -e "\n[TEST 13] Minimum characters per type"
python3 password_generator.py -F -m 3 -L 16 -n || { echo "[FAIL] Test 13 failed"; script_exit 13; }

# Test 14: Pattern-based generation
echo -e "\n[TEST 14] Pattern-based generation"
python3 password_generator.py -p 'lluuddss' -n || { echo "[FAIL] Test 14 failed"; script_exit 14; }

# Test 15: Pattern with blank
echo -e "\n[TEST 15] Pattern with blank character"
python3 password_generator.py -p 'lluubbdd' -n || { echo "[FAIL] Test 15 failed"; script_exit 15; }

# Test 16: Multiple passwords
echo -e "\n[TEST 16] Generate multiple passwords"
python3 password_generator.py -F -L 12 -c 3 --label "Batch Test" --category "Testing" -n || { echo "[FAIL] Test 16 failed"; script_exit 16; }

# ============================================
# HISTORY VIEWING TESTS
# ============================================

# Test 17: View history (table format)
echo -e "\n[TEST 17] View password history (table format)"
python3 password_generator.py -H || { echo "[FAIL] Test 17 failed"; script_exit 17; }

# Test 18: View history with limit
echo -e "\n[TEST 18] View history with limit"
python3 password_generator.py -H --limit 3 || { echo "[FAIL] Test 18 failed"; script_exit 18; }

# Test 19: Search history by label
echo -e "\n[TEST 19] Search history by label"
python3 password_generator.py -H --search "Gmail" || { echo "[FAIL] Test 19 failed"; script_exit 19; }

# Test 20: Search history by category
echo -e "\n[TEST 20] Search history by category"
python3 password_generator.py -H --search "Email" || { echo "[FAIL] Test 20 failed"; script_exit 20; }

# Test 21: Search history by tags
echo -e "\n[TEST 21] Search history by tags"
python3 password_generator.py -H --search "work" || { echo "[FAIL] Test 21 failed"; script_exit 21; }

# Test 22: Filter by category
echo -e "\n[TEST 22] Filter by category"
python3 password_generator.py -H --filter-category "Email" || { echo "[FAIL] Test 22 failed"; script_exit 22; }

# Test 23: Filter by strength
echo -e "\n[TEST 23] Filter by strength (>= 8)"
python3 password_generator.py -H --filter-strength 8 || { echo "[FAIL] Test 23 failed"; script_exit 23; }

# Test 24: Filter by date
echo -e "\n[TEST 24] Filter by date (since today)"
TODAY=$(date +%Y-%m-%d)
python3 password_generator.py -H --since "$TODAY" || { echo "[FAIL] Test 24 failed"; script_exit 24; }

# Test 25: Combined filters
echo -e "\n[TEST 25] Combined filters (category + strength)"
python3 password_generator.py -H --filter-category "Email" --filter-strength 7 || { echo "[FAIL] Test 25 failed"; script_exit 25; }

# ============================================
# ENTRY MANAGEMENT TESTS
# ============================================

# Test 26: Delete entry by index
echo -e "\n[TEST 26] Delete entry by index"
ENTRY_COUNT=$(python3 password_generator.py -H 2>/dev/null | grep -c "│" || echo "0")
if [ "$ENTRY_COUNT" -gt "2" ]; then
    python3 password_generator.py --delete-entry 1 || { echo "[FAIL] Test 26 failed"; script_exit 26; }
else
    echo "  -> Skipped (not enough entries to delete)"
fi

# Test 27: View history after deletion
echo -e "\n[TEST 27] View history after deletion"
python3 password_generator.py -H || { echo "[FAIL] Test 27 failed"; script_exit 27; }

# ============================================
# EDGE CASES AND VALIDATION TESTS
# ============================================

# Test 28: Minimum length enforcement
echo -e "\n[TEST 28] Minimum length enforcement (should auto-increase to 8)"
python3 password_generator.py -F -L 5 -n || { echo "[FAIL] Test 28 failed"; script_exit 28; }

# Test 29: Long password
echo -e "\n[TEST 29] Long password (32 characters)"
python3 password_generator.py -F -L 32 --label "Long Password" --category "Testing" -n || { echo "[FAIL] Test 29 failed"; script_exit 29; }

# Test 30: Very long password
echo -e "\n[TEST 30] Very long password (64 characters)"
python3 password_generator.py -F -L 64 --label "Very Long Password" --category "Testing" -n || { echo "[FAIL] Test 30 failed"; script_exit 30; }

# Test 31: Complex requirements
echo -e "\n[TEST 31] Complex requirements (all options)"
python3 password_generator.py -F -e -r -m 2 -b -L 24 --label "Complex Test" --category "Testing" --tags "complex,all-options" -n || { echo "[FAIL] Test 31 failed"; script_exit 31; }

# Test 32: Pattern with wildcard
echo -e "\n[TEST 32] Pattern with wildcard"
python3 password_generator.py -p '****lluu' -n || { echo "[FAIL] Test 32 failed"; script_exit 32; }

# ============================================
# FILE OPERATIONS TESTS
# ============================================

# Test 33: No save option
echo -e "\n[TEST 33] No save option (verify not saved)"
BEFORE_COUNT=$(python3 password_generator.py -H 2>/dev/null | grep -c "│" || echo "0")
python3 password_generator.py -F -L 16 -n --label "No Save Test" || { echo "[FAIL] Test 33 failed"; script_exit 33; }
AFTER_COUNT=$(python3 password_generator.py -H 2>/dev/null | grep -c "│" || echo "0")
if [ "$BEFORE_COUNT" -ne "$AFTER_COUNT" ]; then
    echo "[FAIL] Test 33 failed - password was saved when --no-save was used"
    script_exit 33
fi

# Test 34: Help message
echo -e "\n[TEST 34] Help message"
python3 password_generator.py -h > /dev/null || { echo "[FAIL] Test 34 failed"; script_exit 34; }

# Test 35: Cleanup (secure deletion)
echo -e "\n[TEST 35] Secure deletion (cleanup)"
python3 password_generator.py -C || { echo "[FAIL] Test 35 failed"; script_exit 35; }

# Test 36: Verify cleanup worked
echo -e "\n[TEST 36] Verify cleanup worked"
python3 password_generator.py -H 2>&1 | grep -q "No password history available" || { echo "[FAIL] Test 36 failed - history still exists after cleanup"; script_exit 36; }

echo -e "\n=========================================="
echo "All tests completed successfully!"
echo "=========================================="

# Explicitly restore shell state before exiting
# This ensures state is restored even if trap doesn't fire when sourced
restore_shell_state

# Remove trap since we've restored manually
trap - EXIT

# Exit/return appropriately
if [[ "${_IS_SOURCED}" -eq 1 ]]; then
    return 0
else
    exit 0
fi
