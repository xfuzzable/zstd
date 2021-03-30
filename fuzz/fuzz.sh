FUZZ_FILE="@@"

# ===== Uncomment following lines to enable persist mode =====
FUZZ_FILE="FUZZ_FILE"
# ============================================================

afl-fuzz -m none -i in/ -o out -- ./build/programs/zstd $FUZZ_FILE -o /dev/null