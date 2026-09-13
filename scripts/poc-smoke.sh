#!/usr/bin/env bash
# Linux process-level smoke test. Uses disposable roots, never the user's setup.
set -Eeuo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_bin=${QUICSYNC_BIN:-"$repo/target/debug/quicsync"}
destination_bin=${QUICSYNCD_BIN:-"$repo/target/debug/quicsyncd"}
[[ $source_bin = /* && $destination_bin = /* ]] || {
    echo "Binary overrides must be absolute paths" >&2
    exit 1
}
work=$(mktemp -d)
daemon=
cleanup() {
    if [[ -n $daemon ]]; then
        kill "$daemon" 2>/dev/null || true
        wait "$daemon" 2>/dev/null || true
    fi
    if [[ ${KEEP_SMOKE_FILES:-0} = 1 ]]; then
        echo "Smoke files: $work"
    else
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'echo "Smoke failed; logs:" >&2; tail -n 40 "$work"/*.log >&2' ERR
umask 077
mkdir "$work/source" "$work/destination"
src="$work/source"
dst="$work/destination"
source_pin=$(cd "$src" && "$source_bin" init)
destination_pin=$(cd "$dst" && "$destination_bin" init)
printf 'listen_address = "127.0.0.1:0"\n[[roots]]\nid = "smoke"\npath = "."\nauthorized_peers = ["%s"]\n' \
    "$source_pin" > "$dst/.quicsync/destination.toml"
(cd "$dst" && exec "$destination_bin" serve) > "$work/daemon.log" 2>&1 &
daemon=$!
address=
for ((i=0; i<200; i++)); do
    address=$(sed -n 's/^listening on //p' "$work/daemon.log")
    [[ -n $address ]] && break
    kill -0 "$daemon"
    sleep 0.05
done
[[ -n $address ]]
printf 'root_id = "smoke"\ndestination = "%s"\npeer_pin = "%s"\n' \
    "$address" "$destination_pin" > "$src/.quicsync/source.toml"
printf 'target/\n' > "$src/.gitignore"
cp "$src/.gitignore" "$dst/.gitignore"
mkdir "$src/target" "$dst/target" "$src/.git" "$dst/.git"
printf 'source ignored' > "$src/target/source-only"
printf 'destination ignored' > "$dst/target/destination-only"
printf 'source protected' > "$src/.git/sentinel"
printf 'destination protected' > "$dst/.git/sentinel"
cp "$dst/.quicsync/destination.toml" "$work/original-config"

# Synthetic codebase-shaped fixture: 2,048 files of roughly 4 KiB in 64 directories.
printf -v payload '%04096d' 0
for ((dir=0; dir<64; dir++)); do
    mkdir "$src/package-$dir"
    for ((file=0; file<32; file++)); do
        printf '%s\n' "$payload" > "$src/package-$dir/file-$file"
    done
done
mkdir "$src/empty"
ln -s package-0/file-0 "$src/link"
chmod 755 "$src/package-0/file-0"

sync_once() {
    (cd "$src" && timeout 60 "$source_bin" sync) > "$work/$1.log" 2>&1
    grep -q 'sync complete' "$work/$1.log"
}
verify() {
    diff -r --no-dereference --exclude=.quicsync --exclude=.git --exclude=target "$src" "$dst"
    [[ ! -e "$dst/target/source-only" ]]
    [[ $(< "$dst/target/destination-only") = "destination ignored" ]]
    [[ $(< "$dst/.git/sentinel") = "destination protected" ]]
    cmp "$work/original-config" "$dst/.quicsync/destination.toml"
    [[ $(stat -c %a "$dst/package-0/file-0") = 755 ]]
    [[ $(readlink "$dst/link") = package-0/file-0 ]]
}
sync_once initial
verify
inode=$(stat -c %i "$dst/package-0/file-0")
sync_once unchanged
verify
[[ $(stat -c %i "$dst/package-0/file-0") = "$inode" ]]

printf 'small edit\n' >> "$src/package-0/file-0"
rm "$src/package-0/file-1"
rmdir "$src/empty"
mkdir "$src/new-directory"
printf 'new file\n' > "$src/new-directory/file"
sync_once small
verify

for ((dir=0; dir<4; dir++)); do
    for ((file=0; file<32; file++)); do
        # Keep the deleted path deleted.
        [[ $dir = 0 && $file = 1 ]] && continue
        printf '%s\n%s\n' "$payload" "$payload" >> "$src/package-$dir/file-$file"
    done
done
sync_once medium
verify

printf 'interactive edit\n' >> "$src/package-1/file-0"
(cd "$src" && printf '\n\n' | timeout 60 "$source_bin" interactive) > "$work/interactive.log" 2>&1
[[ $(grep -c 'sync complete' "$work/interactive.log") = 2 ]]
verify
for stage in 'source notification' 'source indexing' 'source transferring'; do
    grep -q "$stage: start" "$work/initial.log"
    grep -q "$stage: stop" "$work/initial.log"
done
for stage in indexing planning requesting staging committing; do
    [[ $(grep -c "destination $stage: start" "$work/daemon.log") = 6 ]]
    [[ $(grep -c "destination $stage: stop" "$work/daemon.log") = 6 ]]
done
echo "PASS: six process-pair syncs; initial/no-change/small/medium/interactive; external tree checks"
for log in initial unchanged small medium interactive; do
    echo "=== $log ==="
    cat "$work/$log.log"
done
echo "=== daemon ==="
cat "$work/daemon.log"
