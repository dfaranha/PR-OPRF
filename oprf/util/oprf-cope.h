#ifndef OPRF_COPE_H__
#define OPRF_COPE_H__

#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-vole/utility.h"
#include "oprf/util/gmp-prg-fp.h"
#include <vector>

template <typename IO> class OprfCope {
public:
  int party;
  size_t m;
  IO *io;
  mpz_class delta;
  GMP_PRG_FP *G0 = nullptr;
  GMP_PRG_FP *G1 = nullptr;
  bool *delta_bool = nullptr;

  OprfCope(int party, IO *io, size_t m) {
    this->party = party;
    this->m = m;
    this->io = io;
  }

  ~OprfCope() {
    if (G0 != nullptr)
      delete[] G0;
    if (G1 != nullptr)
      delete[] G1;
    if (delta_bool != nullptr)
      delete[] delta_bool;    
  }

  // sender
  void initialize(mpz_class delta) {
    this->delta = delta;
    delta_bool = new bool[m];
    delta384_to_bool();

    block* K = new block[m];
    OTCO<IO> otco(io);
    otco.recv(K, delta_bool, m);

    G0 = new GMP_PRG_FP[m];
    for (int i = 0; i < m; ++i)
      G0[i].reseed(K + i);

    delete[] K;
  }

  // recver
  void initialize() {
    block *K = new block[2 * m];
    PRG prg;
    prg.random_block(K, 2 * m);
    OTCO<IO> otco(io);
    otco.send(K, K + m, m);

    G0 = new GMP_PRG_FP[m];
    G1 = new GMP_PRG_FP[m];
    for (int i = 0; i < m; ++i) {
      G0[i].reseed(K + i);
      G1[i].reseed(K + m + i);
    }

    delete[] K;
  }

  // sender
  mpz_class extend() {
    std::vector<mpz_class> w(m);
    std::vector<mpz_class> v(m);

    for (int i = 0; i < m; ++i) w[i] = G0[i].sample();

    uint8_t *vvv = new uint8_t[m * oprf_P_len / 8];
    io->recv_data(vvv, m * oprf_P_len / 8);

    for (int i = 0; i < m; ++i) v[i] = hex_compose(vvv + i * oprf_P_len / 8);
    delete[] vvv;

    for (int i = 0; i < m; ++i) {
      if (delta_bool[i]) {
        w[i] += v[i];
        w[i] %= gmp_P;
      }
    }

    return prm2pr(w);
  }

  // sender batch
  // void extend(__uint128_t *ret, int size) {
  //   uint64_t *w = new uint64_t[m * size];
  //   uint64_t *v = new uint64_t[m * size];
  //   for (int i = 0; i < m; ++i) {
  //     G0[i].random_data(&w[i * size], size * sizeof(uint64_t));
  //     for (int j = 0; j < size; ++j) {
  //       w[i * size + j] = mod(w[i * size + j]);
  //     }
  //   }

  //   uint64_t ch[2];
  //   ch[0] = (uint64_t)0;
  //   for (int i = 0; i < m; ++i) {
  //     for (int j = 0; j < size; ++j) {
  //       io->recv_data(&v[i * size + j], sizeof(uint64_t));
  //       ch[1] = v[i * size + j];
  //       v[i * size + j] = add_mod(w[i * size + j], ch[delta_bool[i]]);
  //     }
  //   }

  //   prm2pr(ret, v, size);

  //   delete[] w;
  //   delete[] v;
  // }

  // recver
  mpz_class extend(mpz_class u) {

    std::vector<mpz_class> w0(m);
    uint8_t *tau = new uint8_t[m * oprf_P_len / 8];
    for (int i = 0; i < m; ++i) {
      mpz_class w1;
      w0[i] = G0[i].sample();
      w1 = G1[i].sample();
      w1 = (w1 + u) % gmp_P;
      w1 = gmp_P - w1;
      hex_decompose((w0[i] + w1) % gmp_P, tau + i * oprf_P_len / 8);
    }

    io->send_data(tau, m * oprf_P_len / 8);
    io->flush();
    delete[] tau;

    return prm2pr(w0);
  }

  // recver batch
  // void extend(__uint128_t *ret, uint64_t *u, int size) {
  //   uint64_t *w0 = new uint64_t[m * size];
  //   uint64_t *w1 = new uint64_t[m * size];
  //   for (int i = 0; i < m; ++i) {
  //     G0[i].random_data(&w0[i * size], size * sizeof(uint64_t));
  //     G1[i].random_data(&w1[i * size], size * sizeof(uint64_t));
  //     for (int j = 0; j < size; ++j) {
  //       w0[i * size + j] = mod(w0[i * size + j]);
  //       w1[i * size + j] = mod(w1[i * size + j]);

  //       w1[i * size + j] = add_mod(w1[i * size + j], u[j]);
  //       w1[i * size + j] = PR - w1[i * size + j];
  //       uint64_t tau = add_mod(w0[i * size + j], w1[i * size + j]);
  //       io->send_data(&tau, sizeof(uint64_t));
  //       //			io->flush();
  //     }
  //   }

  //   prm2pr(ret, w0, size);

  //   delete[] w0;
  //   delete[] w1;
  // }

  inline void delta384_to_bool() {
    bit_decompose(delta, delta_bool);
  }

//   void delta64_to_bool(bool *bdata, __uint128_t u128) {
//     uint64_t *ptr = (uint64_t *)(&u128);
//     uint64_t in = ptr[0];
//     for (int i = 0; i < m; ++i) {
//       bdata[i] = ((in & 0x1LL) == 1);
//       in >>= 1;
//     }
//   }

  mpz_class prm2pr(std::vector<mpz_class> &a) {
    mpz_class ret = 0;
    mpz_class tmp;
    for (size_t i = 0; i < m; ++i) {
      tmp = (a[i] << i) % gmp_P;
      ret = (ret + tmp) % gmp_P;
    }
    return ret;
  }



  // void prm2pr(__uint128_t *ret, __uint128_t *a, int size) {
  //   memset(ret, 0, size * sizeof(__uint128_t));
  //   __uint128_t tmp;
  //   for (int i = 0; i < m; ++i) {
  //     for (int j = 0; j < size; ++j) {
  //       tmp = mod(a[i * size + j] << i, pr);
  //       ret[j] = mod(ret[j] + tmp, pr);
  //     }
  //   }
  // }

  // void prm2pr(__uint128_t *ret, uint64_t *a, int size) {
  //   memset(ret, 0, size * sizeof(__uint128_t));
  //   __uint128_t tmp;
  //   for (int i = 0; i < m; ++i) {
  //     for (int j = 0; j < size; ++j) {
  //       tmp = (__uint128_t)a[i * size + j];
  //       tmp = mod(tmp << i, pr);
  //       ret[j] = (__uint128_t)add_mod(ret[j], tmp);
  //     }
  //   }
  // }

  // debug function
  // void check_triple(uint64_t *a, __uint128_t *b, int sz) {
  //   if (party == ALICE) {
  //     io->send_data(a, sizeof(uint64_t));
  //     io->send_data(b, sz * sizeof(__uint128_t));
  //   } else {
  //     uint64_t delta;
  //     __uint128_t *c = new __uint128_t[sz];
  //     io->recv_data(&delta, sizeof(uint64_t));
  //     io->recv_data(c, sz * sizeof(__uint128_t));
  //     for (int i = 0; i < sz; ++i) {
  //       __uint128_t tmp = mod((__uint128_t)a[i] * delta, pr);
  //       tmp = mod(tmp + c[i], pr);
  //       if (tmp != b[i]) {
  //         std::cout << "wrong triple" << i << std::endl;
  //         abort();
  //       }
  //     }
  //   }
  //   std::cout << "pass check" << std::endl;
  // }
};

#endif
