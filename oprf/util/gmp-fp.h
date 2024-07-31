#ifndef GMP_FP
#define GMP_FP

#include "emp-tool/emp-tool.h"
#include <gmpxx.h>
#include <vector>
#include <string>

using namespace std;
using namespace emp;

static mpz_class gmp_F("115792089237316195423570985008687907853269984665640564039457584007913129606561");
static mpz_class gmp_P = (gmp_F << 128) + 1;
static mpz_class gmp_P_m2 = gmp_P - 2;
//static mpz_class gmp_P("39402006196394479212279040100143613805079739270465446667948293404245721760140286615427945036794788117771363932962817");
// static std::vector<bool> bit_gmp_P_m2;
// static std::vector<bool> bit_gmp_F;
#define oprf_P_len 384

void bit_decompose(mpz_class num, bool *out) {
    for (size_t i = 0; i < oprf_P_len; i++) {
        out[i] = ((num & 1) == 1);
        num >>= 1;
    }
}

void bit_decompose(mpz_class num, int size, std::vector<bool> &out) {
    for (size_t i = 0; i < size; i++) {
        out[i] = ((num & 1) == 1);
        num >>= 1;
    }
}

// the setup needs to be adjusted if P is changed
// void gmp_setup() {
//     bit_gmp_P_m2.resize(384);
//     bit_decompose(gmp_P_m2, 384, bit_gmp_P_m2);
//     bit_gmp_F.resize(256);
//     bit_decompose(gmp_F, 256, bit_gmp_F);
// }

static mpz_class minorone("-1");

mpz_class gmp_inverse(const mpz_class &in) {
    
    mpz_class res;
    mpz_powm(res.get_mpz_t(), in.get_mpz_t(), minorone.get_mpz_t(), gmp_P.get_mpz_t());
    // mpz_class res = 1;
    // mpz_class sq = in;
    // for (int i = 0; i < 384; i++) {
    //     if (bit_gmp_P_m2[i]) res = (res * sq) % gmp_P;
    //     sq = sq * sq % gmp_P;
    // }
    return res;
}

mpz_class gmp_raise(const mpz_class &in) {
    mpz_class res;
    mpz_powm(res.get_mpz_t(), in.get_mpz_t(), gmp_F.get_mpz_t(), gmp_P.get_mpz_t());
    // mpz_class sq = in;
    // for (int i = 0; i < 256; i++) {
    //     if (bit_gmp_F[i]) res = (res * sq) % gmp_P;
    //     sq = sq * sq % gmp_P;
    // }
    return res;
}


static std::vector<mpz_class> zk_coeff;

void generate_coeff(int epsilon) {
    int coeff_cnt = 1 << epsilon;
    auto start = clock_start();
    zk_coeff.resize(coeff_cnt+1);
    //std::vector<mpz_class> coeff(coeff_cnt+1);
    mpz_class acc_up = 1;
    mpz_class acc_down = 1;
    for (int i = 0; i <= coeff_cnt; i++) {
      zk_coeff[i] = acc_up * gmp_inverse(acc_down) % gmp_P;
      acc_up = acc_up * (coeff_cnt-i) % gmp_P;
      acc_down = acc_down * (i+1) % gmp_P;
    }
    cout << "Preparing zk coeffients require " << time_from(start) << " us" << endl;
}

mpz_class bit_compose(bool *in) {
    string tmp = "";
    for (int i = oprf_P_len - 1;  i >= 0; i--) tmp += in[i] ? "1" : "0";
    return mpz_class(tmp, 2);
}

void hex_decompose(mpz_class num, uint8_t *out) {
    mpz_export(out, NULL, -1, 1, 0, 0, num.get_mpz_t());
}

const string hex_tb[] = {"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
                        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", 
                        "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
                        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
                        "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
                        "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
                        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
                        "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
                        "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
                        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
                        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
                        "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
                        "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
                        "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
                        "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
                        "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"};

void hex_compose(mpz_class &res, uint8_t *in) {
    mp_limb_t *res_p;
    res_p = mpz_limbs_write(res.get_mpz_t(), 8*48 / GMP_LIMB_BITS);
    memcpy(res_p, in, 48);
    mpz_limbs_finish(res.get_mpz_t(), 8*48 / GMP_LIMB_BITS);
    //mpz_import(res.get_mpz_t(), 48, -1, 1, 0, 0, in);
}

mpz_class hex_compose(uint8_t *in) {
    mpz_class res;
    hex_compose(res, in);
    return res;
}



#endif