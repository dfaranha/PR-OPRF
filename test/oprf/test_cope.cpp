#include <gmpxx.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include "oprf/oprf.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include "comm_test.h"
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO<NetIO> *ios[threads];
  for (int i = 0; i < threads; ++i)
    ios[i] = new BoolIO<NetIO>(
        new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i),
        party == ALICE);

  std::cout << std::endl
            << "------------ TEST COPE ------------"
            << std::endl
            << std::endl;

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);  

  // tmptmp
  if (party == ALICE) {
    GMP_PRG_FP prgdelta;
    mpz_class delta = prgdelta.sample();
    OprfCope<BoolIO<NetIO>> cope(party, ios[0], oprf_P_len);
    cope.initialize(delta);
    std::vector<mpz_class> v(50000);
    auto start = clock_start();
    cope.extend(v, 50000);
    double ttt = time_from(start);
    std::cout << "batch triple generation: " << ttt << " us" << std::endl; 
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    cope.check_triple(v, v, 50000);
  } else {
    OprfCope<BoolIO<NetIO>> cope(party, ios[0], oprf_P_len);
    cope.initialize();  
    GMP_PRG_FP prg;
    std::vector<mpz_class> u(50000);
    std::vector<mpz_class> w(50000);
    for (int i = 0; i < 50000; i++) u[i] = prg.sample();
    auto start = clock_start();
    cope.extend(w, u, 50000);
    double ttt = time_from(start);
    std::cout << "batch triple generation: " << ttt << " us" << std::endl;    
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    cope.check_triple(u, w, 50000);
  }


  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}

