#include <gmpxx.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include "oprf/oprf.h"

using namespace std;

int main() {
    GMP_PRG_FP prg;
    mpz_class res;
    for (int i = 0; i < 100000; i++) {
        prg.sample();
        //cout << res << endl;
    }
    return 0;
}