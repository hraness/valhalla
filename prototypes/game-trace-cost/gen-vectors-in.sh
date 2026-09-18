#!/bin/sh
# Regenerates vectors.in from ../../crates/vhalla-witness/tests/vectors/*.txt.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out="$script_dir/vectors.in"
printf '[\n' > "$out"
for file in "$script_dir"/../../crates/vhalla-witness/tests/vectors/*.txt; do
    name=$(basename "$file")
    printf '    ("%s", include_str!("../../crates/vhalla-witness/tests/vectors/%s")),\n' "$name" "$name" >> "$out"
done
printf ']\n' >> "$out"
