#ifndef GMP_PRG_FP_H
#define GMP_PRG_FP_H

#include "oprf/util/gmp-fp.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include <string>

using namespace emp;

static const char int2hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

class GMP_PRG_FP {
public:
    PRG prg;
    GMP_PRG_FP() {}
    GMP_PRG_FP(block* seed) {
        prg.reseed(seed);
    }
    
    void reseed(block* seed) {
        prg.reseed(seed);
    }

    void sample(mpz_class& res) {
        block K[3];
        string str_res;
        while (true) {     
            prg.random_block(K, 3);
            str_res = "";
            for (size_t i = 0; i < 3; i++) {
                uint64_t tmp;
                tmp = HIGH64(K[i]);
                for (size_t t = 0; t < 16; t++, tmp >>= 4) {
                    str_res += int2hex[tmp&0xf];
                }
                tmp = LOW64(K[i]);
                for (size_t t = 0; t < 16; t++, tmp >>= 4) {
                    str_res += int2hex[tmp&0xf];
                }
            }
            res.set_str(str_res.c_str(), 16);
            //res = mpz_class(str_res);
            if (res < gmp_P) break;
            std::cout << "re-sample" << std::endl;
        }
    }

    mpz_class sample() {
        mpz_class res;
        block K[3];
        string str_res;
        while (true) {     
            prg.random_block(K, 3);
            str_res = "";
            for (size_t i = 0; i < 3; i++) {
                uint64_t tmp;
                tmp = HIGH64(K[i]);
                for (size_t t = 0; t < 16; t++, tmp >>= 4) {
                    str_res += int2hex[tmp&0xf];
                }
                tmp = LOW64(K[i]);
                for (size_t t = 0; t < 16; t++, tmp >>= 4) {
                    str_res += int2hex[tmp&0xf];
                }
            }
            res.set_str(str_res.c_str(), 16);
            //res = mpz_class(str_res);
            if (res < gmp_P) break;
            std::cout << "re-sample" << std::endl;
        }
        return res;
    }    
};

#endif