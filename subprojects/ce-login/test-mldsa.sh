#!/bin/bash
#
# Reusable round-trip test for ACF signature algorithms.
#
# Exercises both the development (`create`) and production (`create_prod -v2`)
# flows for the legacy RSA-2048/SHA-512 signature and the ML-DSA-87 signature,
# plus negative cases (wrong password, wrong key type, tampered signature).
#
# Usage:
#   ./test-mldsa.sh
#
# The celogin_cli binary is located via (in order): $CELOGIN_CLI,
# ./build-mldsa/celogin_cli, ./build/celogin_cli. Required keys are generated
# on demand (RSA lab keys are committed; ML-DSA keys are created if missing).

set -u
cd "$(dirname "$0")" || exit 1

# ---- locate binary ----------------------------------------------------------
CLI="${CELOGIN_CLI:-}"
if [ -z "$CLI" ]; then
    for candidate in ./build-mldsa/celogin_cli ./build/celogin_cli; do
        if [ -x "$candidate" ]; then CLI="$candidate"; break; fi
    done
fi
if [ -z "$CLI" ] || [ ! -x "$CLI" ]; then
    echo "ERROR: celogin_cli not found. Build it (meson setup build -Dbin=true && ninja -C build)"
    echo "       or set CELOGIN_CLI to the binary path."
    exit 1
fi
echo "Using binary: $CLI"

# ---- keys -------------------------------------------------------------------
RSA_PKEY=p10-celogin-lab-pkey.der
RSA_PUB=p10-celogin-lab-pub.der
MLDSA_PKEY=p12-celogin-lab-pkey.der
MLDSA_PUB=p12-celogin-lab-pub.der

if [ ! -f "$RSA_PKEY" ] || [ ! -f "$RSA_PUB" ]; then
    echo "ERROR: RSA lab keys ($RSA_PKEY / $RSA_PUB) are missing."
    exit 1
fi
if [ ! -f "$MLDSA_PKEY" ] || [ ! -f "$MLDSA_PUB" ]; then
    echo "Generating ML-DSA-87 test keys..."
    openssl genpkey -algorithm ML-DSA-87 -outform DER -out "$MLDSA_PKEY" || exit 1
    openssl pkey -in "$MLDSA_PKEY" -inform DER -pubout -outform DER -out "$MLDSA_PUB" || exit 1
fi

# ---- harness ----------------------------------------------------------------
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PASS=0
FAIL=0

# expect_pass <description> <command...>
expect_pass() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"; PASS=$((PASS+1))
    else
        echo "  FAIL: $desc (expected success, got rc=$?)"; FAIL=$((FAIL+1))
    fi
}

# expect_fail <description> <command...>
expect_fail() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "  FAIL: $desc (expected failure, got success)"; FAIL=$((FAIL+1))
    else
        echo "  PASS: $desc"; PASS=$((PASS+1))
    fi
}

# ---- development flow -------------------------------------------------------
echo
echo "== Development flow (key type selects the signature algorithm) =="

RSA_ACF="$WORK/rsa_dev.acf"
expect_pass "RSA  create" \
    "$CLI" create -m P10,dev,UNSET -p 0penBmc -e 2035-12-25 -k "$RSA_PKEY" -o "$RSA_ACF"
expect_pass "RSA  verify (correct password)" \
    "$CLI" verify -i "$RSA_ACF" -k "$RSA_PUB" -p 0penBmc -s UNSET
expect_pass "RSA  decode" \
    "$CLI" decode -i "$RSA_ACF" -k "$RSA_PUB"
expect_fail "RSA  verify (wrong password)" \
    "$CLI" verify -i "$RSA_ACF" -k "$RSA_PUB" -p wrongpw -s UNSET

MLDSA_ACF="$WORK/mldsa_dev.acf"
expect_pass "MLDSA create" \
    "$CLI" create -m P11,dev,UNSET -p 0penBmc -e 2035-12-25 -k "$MLDSA_PKEY" -o "$MLDSA_ACF"
expect_pass "MLDSA verify (correct password)" \
    "$CLI" verify -i "$MLDSA_ACF" -k "$MLDSA_PUB" -p 0penBmc -s UNSET
expect_pass "MLDSA decode" \
    "$CLI" decode -i "$MLDSA_ACF" -k "$MLDSA_PUB"
expect_fail "MLDSA verify (wrong password)" \
    "$CLI" verify -i "$MLDSA_ACF" -k "$MLDSA_PUB" -p wrongpw -s UNSET

# ---- cross-algorithm / tamper negatives -------------------------------------
echo
echo "== Negative cases =="
expect_fail "MLDSA ACF verified with RSA public key" \
    "$CLI" verify -i "$MLDSA_ACF" -k "$RSA_PUB" -p 0penBmc -s UNSET
expect_fail "RSA ACF verified with ML-DSA public key" \
    "$CLI" verify -i "$RSA_ACF" -k "$MLDSA_PUB" -p 0penBmc -s UNSET

TAMPER="$WORK/mldsa_tampered.acf"
cp "$MLDSA_ACF" "$TAMPER"
# Flip a byte near the end (within the signature) to invalidate it.
python3 -c "d=bytearray(open('$TAMPER','rb').read()); d[-10]^=0x01; open('$TAMPER','wb').write(d)"
expect_fail "MLDSA tampered signature rejected" \
    "$CLI" verify -i "$TAMPER" -k "$MLDSA_PUB" -p 0penBmc -s UNSET

# ---- production flow (signature produced externally via openssl) ------------
echo
echo "== Production flow (create_prod -v2, external signing) =="

prod_roundtrip() {
    # $2 (private key path) is referenced inside the caller-supplied sign_cmd.
    local label="$1" pub="$3" algo_flag="$4" sign_cmd="$5"
    local json="$WORK/${label}_json.txt"
    local pw="$WORK/${label}_pw.txt"
    local sig="$WORK/${label}_sig.bin"
    local acf="$WORK/${label}_acf.bin"

    # Step 1: create JSON + password
    if ! "$CLI" create_prod -v2 -t service -n $algo_flag \
            -m P11,dev,UNSET -e 2035-01-01 -j "$json" -p "$pw" >/dev/null 2>&1; then
        echo "  FAIL: $label create_prod step1"; FAIL=$((FAIL+1)); return
    fi
    # Step 2: external signing over the JSON
    if ! eval "$sign_cmd" >/dev/null 2>&1; then
        echo "  FAIL: $label external signing"; FAIL=$((FAIL+1)); return
    fi
    # Step 3: package JSON + signature into ACF. The V2 packaging path writes
    # the algorithm OID, so it is used for both RSA and ML-DSA (-t satisfies
    # validation; the type-specific fields already live in the JSON).
    if ! "$CLI" create_prod -v2 -t service $algo_flag \
            -j "$json" -s "$sig" -o "$acf" -c "test-mldsa" >/dev/null 2>&1; then
        echo "  FAIL: $label create_prod packaging"; FAIL=$((FAIL+1)); return
    fi
    # Verify
    local password; password=$(cat "$pw")
    expect_pass "$label production round-trip verify" \
        "$CLI" verify -i "$acf" -k "$pub" -p "$password" -s UNSET
}

# RSA: sign the SHA-512 digest of the JSON
prod_roundtrip "rsa" "$RSA_PKEY" "$RSA_PUB" "" \
    "openssl dgst -sign $RSA_PKEY -sha512 -keyform DER -out \$WORK/rsa_sig.bin \$WORK/rsa_json.txt"
# ML-DSA: sign the JSON message directly (-rawin / pure ML-DSA)
prod_roundtrip "mldsa" "$MLDSA_PKEY" "$MLDSA_PUB" "--algorithm mldsa87" \
    "openssl pkeyutl -sign -inkey $MLDSA_PKEY -keyform DER -rawin -in \$WORK/mldsa_json.txt -out \$WORK/mldsa_sig.bin"

# ---- summary ----------------------------------------------------------------
echo
echo "================================"
echo "Results: $PASS passed, $FAIL failed"
echo "================================"
[ "$FAIL" -eq 0 ]
