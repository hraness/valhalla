#!/bin/sh
# Regenerates vectors.in from ../witness-restatement/vectors/*.txt.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out="$script_dir/vectors.in"
printf '[\n' > "$out"
for file in "$script_dir"/../witness-restatement/vectors/*.txt; do
    name=$(basename "$file")
    printf '    ("%s", include_str!("../witness-restatement/vectors/%s")),\n' "$name" "$name" >> "$out"
done
printf ']\n' >> "$out"
