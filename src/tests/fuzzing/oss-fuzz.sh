#!/bin/bash -eu

# This script plays the role of build.sh in OSS-Fuzz.  If only minor
# changes are required such as changing the fuzzing targets, a PR in
# the OSS-Fuzz repository is not needed and they can be done here.

# Compile krb5 for oss-fuzz.
pushd src/
autoreconf
./configure CFLAGS="-fcommon $CFLAGS" CXXFLAGS="-fcommon $CXXFLAGS" \
    --enable-static --disable-shared --enable-ossfuzz
make
popd

# Copy fuzz targets and seed corpus to $OUT.
pushd src/tests/fuzzing

fuzzers=("fuzz_chpw" "fuzz_gss" "fuzz_json" "fuzz_krad" "fuzz_krb5_ticket"
        "fuzz_marshal_cred" "fuzz_marshal_princ" "fuzz_ndr" "fuzz_pac"
        "fuzz_profile" "fuzz_util")

for fuzzer in "${fuzzers[@]}"; do
    cp "$fuzzer" "$OUT/$fuzzer"
    zip -r "${OUT}/${fuzzer}_seed_corpus.zip" "${fuzzer}_seed_corpus"
done

popd
