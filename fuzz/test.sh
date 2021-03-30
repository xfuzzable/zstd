set -e

FUZZ_FILE=""

# ===== Uncomment following lines to enable persist mode =====
FUZZ_FILE="FUZZ_FILE"
# ============================================================

echo "1" | ./build/programs/zstd $FUZZ_FILE -o /dev/null

echo "1" | afl-showmap -m none -o map1 ./build/programs/zstd $FUZZ_FILE -o /dev/null
echo "asdasd" | afl-showmap -m none -o map2 ./build/programs/zstd $FUZZ_FILE -o /dev/null

MAP1=`cat map1 | md5sum`
MAP2=`cat map2 | md5sum`

rm map1 map2

echo "Map1: $MAP1"
echo "Map2: $MAP2"

if [ "$MAP1" == "$MAP2" ]; then
    tput setaf 1
    echo "Test failed, Map1 and Map2 should be different"
    tput sgr0
    exit 1
else
    tput setaf 2
    echo "Test success"
    tput sgr0
    exit 0
fi