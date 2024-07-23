#ifndef OPRF_FP
#define OPRF_FP

#include <emp-tool/emp-tool.h>
#include <iostream>
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"

class OprfFp {
public:
    __uint128_t value[3];

    OprfFp() {}

    OprfFp(__uint128_t a, __uint128_t b, __uint128_t c) {
        value[2] = a;
        value[1] = b;
        value[0] = c;
    }

    OprfFp(block a, block b, block c) {
        memcpy(&value[2], &a, 128);
        memcpy(&value[1], &b, 128);
        memcpy(&value[0], &c, 128);
    }

    OprfFp(__uint128_t value[]) {
        this->value[2] = value[2];
        this->value[1] = value[1];
        this->value[0] = value[0];
    }

    void print() {
        cout << (uint64_t)HIGH64(value[2]) << ' ' << (uint64_t)LOW64(value[2]) << ' '
             << (uint64_t)HIGH64(value[1]) << ' ' << (uint64_t)LOW64(value[1]) << ' '
             << (uint64_t)HIGH64(value[0]) << ' ' << (uint64_t)LOW64(value[0]) << endl;
    }

    bool bound();

    void reduce_mod();

};

static OprfFp OprfMod(makeBlock(18446744073709551615ULL, 18446744073709551615ULL), makeBlock(18446744073709551615ULL, 18446744073709518241ULL), makeBlock(0ULL, 1ULL));    

bool OprfFp::bound() {
    bool l2 = value[2] < OprfMod.value[2];
    bool l1 = value[1] < OprfMod.value[1];
    bool l0 = value[0] < OprfMod.value[0];
    bool e1 = value[1] == OprfMod.value[1];
    return l2 | l1 | (e1 & l0);
}

void OprfFp::reduce_mod() {
    bool over = false;
    if (value[0] < OprfMod.value[0]) over = true;
    value[0] -= OprfMod.value[0];
    if (over) {
        if (value[1] != 0) over = false;
        value[1] -= 1;
    }
    if (value[1] < OprfMod.value[1]) over = true;
    value[1] -= OprfMod.value[1];
    if (over) value[2] -= 1;
    value[2] -= OprfMod.value[2];
}

void OprfFpAddMod(OprfFp &L, OprfFp &R, OprfFp &O) {
    bool over1, over2, over3; // overflow
    O.value[0] = L.value[0] + R.value[0];
    over1 = O.value[0] < max(L.value[0], R.value[0]);
    O.value[1] = L.value[1] + R.value[1];
    over2 = O.value[1] < max(L.value[1], R.value[1]);
    if (over1) {
        O.value[1] += 1;
        if (O.value[1] == 0) over2 = true;
    }
    O.value[2] = L.value[2] + R.value[2];
    over3 = O.value[2] < max(L.value[2], R.value[2]);
    if (over2) {
        O.value[2] += 1;
        if (O.value[2] == 0) over3 = true;
    }

    if (over3 == false) {
        if (O.bound() == false) O.reduce_mod();
    } else { // overflow
        O.reduce_mod();
    }
}

#endif