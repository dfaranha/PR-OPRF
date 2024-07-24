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
  std::vector<GMP_PRG_FP> G0;
  std::vector<GMP_PRG_FP> G1;
  std::vector<char> delta_bool;

  OprfCope(int party, IO *io, size_t m) {
    this->party = party;
    this->m = m;
    this->io = io;
  }

  // sender
  void initialize(mpz_class delta) {
    this->delta = delta;
    delta_bool.resize(m);
    delta384_to_bool();

    std::vector<block> K(m);
    OTCO<IO> otco(io);

    otco.recv(&K[0], reinterpret_cast<bool*>(delta_bool.data()), m);
    G0.resize(m);
    for (int i = 0; i < m; ++i)
      G0[i].reseed(&K[i]);
  }

  // recver
  void initialize() {
    std::vector<block> K(2 * m);
    PRG prg;
    prg.random_block(&K[0], 2 * m);
    OTCO<IO> otco(io);
    otco.send(&K[0], &K[m], m);

    G0.resize(m);
    G1.resize(m);
    for (int i = 0; i < m; ++i) {
      G0[i].reseed(&K[i]);
      G1[i].reseed(&K[m + i]);
    }
  }

  // sender
  mpz_class extend() {
    std::vector<mpz_class> w(m);
    std::vector<mpz_class> v(m);

    for (int i = 0; i < m; ++i) w[i] = G0[i].sample();

    std::vector<uint8_t> vvv(m * oprf_P_len / 8);
    io->recv_data(&vvv[0], m * oprf_P_len / 8);

    for (int i = 0; i < m; ++i) v[i] = hex_compose(&vvv[i * oprf_P_len / 8]);

    for (int i = 0; i < m; ++i) {
      if (delta_bool[i]) {
        w[i] += v[i];
        w[i] %= gmp_P;
      }
    }

    return prm2pr(w);
  }

  // sender batch
  void extend(std::vector<mpz_class> &ret, const int &size) {
    std::vector<mpz_class> w(m * size);
    std::vector<mpz_class> v(m * size);

    for (int i = 0; i < m; i++) 
      for (int j = 0; j < size; j++) 
        w[i * size + j] = G0[i].sample();

    std::vector<uint8_t> vvv(size * m * oprf_P_len / 8);
    io->recv_data(&vvv[0], size * m * oprf_P_len / 8);

    for (int i = 0; i < m; i++)
      for (int j = 0; j < size; j++)
        v[i * size + j] = hex_compose(&vvv[(i * size + j) * oprf_P_len / 8]);

    for (int i = 0; i < m; ++i) {
      if (delta_bool[i]) {
        for (int j = 0; j < size; ++j) {        
          w[i * size + j] += v[i * size + j];
          w[i * size + j] %= gmp_P;
        }
      }
    }

    prm2pr(ret, w, size);
  }

  // recver
  mpz_class extend(mpz_class u) {
    std::vector<mpz_class> w0(m);
    std::vector<uint8_t> tau(m * oprf_P_len / 8);
    for (int i = 0; i < m; ++i) {
      mpz_class w1;
      w0[i] = G0[i].sample();
      w1 = G1[i].sample();
      w1 = (w1 + u) % gmp_P;
      w1 = gmp_P - w1;
      hex_decompose((w0[i] + w1) % gmp_P, &tau[i * oprf_P_len / 8]);
    }

    io->send_data(&tau[0], m * oprf_P_len / 8);
    io->flush();

    return prm2pr(w0);
  }

  // recver batch
  void extend(std::vector<mpz_class> &ret, std::vector<mpz_class> &u, int size) {
    std::vector<mpz_class> w0(m * size);
    std::vector<uint8_t> tau(size * m * oprf_P_len / 8);
    for (int i = 0; i < m; ++i) {
      mpz_class w1;
      for (int j = 0; j < size; j++) {
        w0[i * size + j] = G0[i].sample();
        w1 = G1[i].sample();
        w1 = (w1 + u[j]) % gmp_P;
        w1 = gmp_P - w1;
        hex_decompose((w0[i * size + j] + w1) % gmp_P, &tau[(i * size + j) * oprf_P_len / 8]);
      }
    }

    io->send_data(&tau[0], size * m * oprf_P_len / 8);
    io->flush();

    prm2pr(ret, w0, size);
  }

  inline void delta384_to_bool() {
    bit_decompose(delta, delta_bool);
  }

  mpz_class prm2pr(std::vector<mpz_class> &a) {
    mpz_class ret = 0;
    mpz_class tmp;
    for (size_t i = 0; i < m; ++i) {
      tmp = (a[i] << i) % gmp_P;
      ret = (ret + tmp) % gmp_P;
    }
    return ret;
  }

  void prm2pr(std::vector<mpz_class> &ret, std::vector<mpz_class> &w, const int &size) {
    ret.resize(size);
    for (int i = 0; i < size; i++) ret[i] = 0;
    mpz_class tmp;
    for (int i = 0; i < m; i++) {
      for (int j = 0; j < size; j++) {
        tmp = (w[i * size + j] << i) % gmp_P;
        ret[j] = (ret[j] + tmp) % gmp_P;
      }
    }
  }

  // debug function
  void check_triple(std::vector<mpz_class> &a, std::vector<mpz_class> &b, int sz) {
    std::vector<uint8_t> hex_de(oprf_P_len / 8);
    if (party == ALICE) {
      hex_decompose(delta, &hex_de[0]);
      io->send_data(&hex_de[0], oprf_P_len / 8);
      io->flush();
    } else {
      io->recv_data(&hex_de[0], oprf_P_len / 8);
      delta = hex_compose(&hex_de[0]);
    }
    for (int i = 0; i < sz; i++) {
      for (int j = 0; j < 48; j++) hex_de[j] = 0;
      if (party == ALICE) {
        hex_decompose(b[i], &hex_de[0]);
        io->send_data(&hex_de[0], oprf_P_len / 8);
        io->flush();
      } else {
        io->recv_data(&hex_de[0], oprf_P_len / 8);
        mpz_class c = hex_compose(&hex_de[0]);
        mpz_class d = (delta * a[i] + c) % gmp_P;
        if (d != b[i]) {
          cout << "wrong triple!" << std::endl;
          abort();
        }
      }
    }
    std::cout << "pass check" << std::endl;
  }
};

#endif
