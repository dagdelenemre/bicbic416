#!/bin/sh
# BicBic416 CTR anahtar akışını PractRand ile test eder.
# Gerekli: make analysis ve PractRand (http://pracrand.sourceforge.net) RNG_test;
# RNG_test PATH üzerinde değilse yolu PRACTRAND ortam değişkeniyle verin.
# Sonuçlar: build/analysis/practrand_R<tur>_<anahtar>.txt
#
# Kullanım: sh analysis/run_practrand.sh
set -u
PR=${PRACTRAND:-RNG_test}
KS=build/analysis/keystream
OUT=build/analysis
[ -x "$KS.exe" ] && KS="$KS.exe"

run() { # tur anahtar sınır
    f="$OUT/practrand_R$1_$2.txt"
    echo "== R=$1 anahtar=$2 sınır=$3" > "$f"
    "$KS" "$1" "$2" | "$PR" stdin32 -tf 2 -tlmax "$3" -multithreaded >> "$f" 2>&1
    echo "bitti: R=$1 $2 $3"
}

# Azaltılmış turlar: şifrenin istatistiksel olarak nerede "kırıldığını" bulmak için.
for r in 1 2 3 4 5 6; do run $r rastgele 1GB; done
# Tam şifre ve önerilen alternatif.
run 8 rastgele 16GB
run 16 sifir 16GB
run 16 rastgele 64GB
