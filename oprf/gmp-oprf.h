#ifndef _GMP_OPRF_
#define _GMP_OPRF_

#include "oprf/oprf.h"
#include "emp-tool/emp-tool.h"

template <typename IO> class Oprf {
public:
  IO *io;
  IO **ios;
  int party;
  int threads;
  mpz_class Delta;
  OprfVoleTriple<IO> vole;

  Oprf(int party, int threads, IO **ios) : vole(party, threads, ios) {
    this->io = ios[0];
    this->ios = ios;
    this->party = party;
    this->threads = threads;

    gmp_setup();
  }

  void setup(mpz_class delta) {
    this->Delta = delta;
    vole.setup(delta);
  }

  void setup() {
    vole.setup();
  }

  // single eval
  void oprf_eval_server() {
    std::vector<uint8_t> ext(48);
    mpz_class share;
    vole.extend_sender(&share, 1);
    io->recv_data(&ext[0], 48);
    mpz_class msg1 = hex_compose(&ext[0]);
    mpz_class msg2 = ((msg1 - share) % gmp_P + gmp_P) % gmp_P;
    GMP_PRG_FP prg;
    mpz_class alphae = prg.sample();
    for (int i = 0; i < 128; i++) alphae = (alphae * alphae) % gmp_P;
    msg2 = (msg2 * alphae) % gmp_P;
    for (int i = 0; i < 48; i++) ext[i] = 0;
    hex_decompose(msg2, &ext[0]);
    io->send_data(&ext[0], 48);
    io->flush();
  }

  mpz_class oprf_eval_client(const mpz_class &x) {
    std::vector<uint8_t> ext(48);
    mpz_class share, a;
    vole.extend_recver(&share, &a, 1);
    mpz_class msg1 = (a * x + share) % gmp_P;
    hex_decompose(msg1, &ext[0]);
    io->send_data(&ext[0], 48);
    io->flush();
    io->recv_data(&ext[0], 48);
    mpz_class msg2 = hex_compose(&ext[0]);

    return gmp_raise(msg2 * gmp_inverse(a) % gmp_P);
  }

  // batch eval
  void oprf_batch_eval_server(const int &sz) {
    std::vector<uint8_t> ext(48 * sz);
    std::vector<mpz_class> share(sz);
    vole.extend_sender(&share[0], sz);
    io->recv_data(&ext[0], 48 * sz);
    mpz_class msg1, msg2, alphae;
    GMP_PRG_FP prg;
    for (int i = 0; i < sz; i++) {
      msg1 = hex_compose(&ext[48 * i]);
      msg2 = ((msg1 - share[i]) % gmp_P + gmp_P) % gmp_P;
      alphae = prg.sample();
      for (int j = 0; j < 128; j++) alphae = (alphae * alphae) % gmp_P;
      msg2 = (msg2 * alphae) % gmp_P;
      for (int j = 48 * i; j < 48 * (i+1); j++) ext[j] = 0;
      hex_decompose(msg2, &ext[48 * i]);
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
  }

  void oprf_batch_eval_client(const mpz_class *x, const int &sz, std::vector<mpz_class> &y) {
    std::vector<uint8_t> ext(48 * sz);
    y.resize(sz);
    std::vector<mpz_class> share(sz), a(sz);
    vole.extend_recver(&share[0], &a[0], sz);
    mpz_class msg1;
    for (int i = 0; i < sz; i++) {
      msg1 = (a[i] * x[i] + share[i]) % gmp_P;
      hex_decompose(msg1, &ext[48 * i]);
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
    io->recv_data(&ext[0], 48 * sz);
    mpz_class msg2;
    for (int i = 0; i < sz; i++) {
      msg2 = hex_compose(&ext[48 * i]);
      y[i] = gmp_raise(msg2 * gmp_inverse(a[i]) % gmp_P);
    }
  }

};


#endif