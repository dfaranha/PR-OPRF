#include "emp-tool/emp-tool.h"
#include "oprf/oprf.h"

using namespace emp;
using namespace std;

int party, port;

void check_triple(NetIO *io, mpz_class *x, mpz_class *y, mpz_class *val, int size) {
  std::vector<uint8_t> ext(48);
  if (party == ALICE) {
    hex_decompose(*x, &ext[0]);
    io->send_data(&ext[0], 48);
    io->flush();
    for (int i = 0; i < size; i++) {
      for (int j = 0; j < 48; j++) ext[j] = 0;
      hex_decompose(y[i], &ext[0]);
      io->send_data(&ext[0], 48);
      io->flush();
    }
  } else {    
    io->recv_data(&ext[0], 48);
    mpz_class delta = hex_compose(&ext[0]);
    for (int i = 0; i < size; ++i) {
      io->recv_data(&ext[0], 48);
      mpz_class xx = hex_compose(&ext[0]);
      mpz_class xxx = (delta * val[i] + xx) % gmp_P;
      if (xxx != y[i]) {
        cout << "error" << endl;
        abort();
      }
    }
    cout << "check pass" << endl;
  }
}

void test_lpn(NetIO *io, int party) {
  OprfBaseVole<NetIO> *svole;

  // ALICE generate delta
  GMP_PRG_FP prg;
  mpz_class Delta = prg.sample();

  // test cases reduced for github action
  int test_n = 10000;
  int test_k = 100;

  std::vector<mpz_class> mac1(test_n);
  std::vector<mpz_class> mac2(test_k);
  std::vector<mpz_class> x1(test_n);
  std::vector<mpz_class> x2(test_k);
  
  if (party == ALICE) {
    svole = new OprfBaseVole<NetIO>(party, io, Delta);    
    svole->triple_gen_send(mac1, test_n);
    svole->triple_gen_send(mac2, test_k);
  } else {
    svole = new OprfBaseVole<NetIO>(party, io);
    svole->triple_gen_recv(mac1, x1, test_n);
    svole->triple_gen_recv(mac2, x2, test_k);
  }

  ThreadPool pool(1);
  OprfLpnFp<10> lpn(test_n, test_k, &pool, pool.size());
  auto start = clock_start();
  if (party == ALICE) {
    lpn.compute_send(&mac1[0], &mac2[0]);
    //check_triple(io, &Delta, mac1, test_n);
  } else {
    lpn.compute_recv(&mac1[0], &x1[0], &mac2[0], &x2[0]);
    //check_triple(io, nullptr, mac1, test_n);
  }
  std::cout << "LPN: " << time_from(start) * 1000.0 / test_n << " ns per entry"
            << std::endl;

  if (party == ALICE) {
    check_triple(io, &Delta, &mac1[0], nullptr, test_n);
  } else {
    check_triple(io, nullptr, &mac1[0], &x1[0], test_n);
  }

  delete svole;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

  std::cout << std::endl
            << "------------ LPN ------------" << std::endl
            << std::endl;
  ;

  test_lpn(io, party);

  delete io;
  return 0;
}
