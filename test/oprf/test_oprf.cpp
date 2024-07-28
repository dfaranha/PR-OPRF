
#include <gmpxx.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include "oprf/oprf.h"
#include "emp-tool/emp-tool.h"
#include "oprf/gmp-oprf.h"
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
            << "------------ TEST OPRF ------------"
            << std::endl
            << std::endl;

  // cout << "#VOLE: "; int test_nn = 10005354;

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);    

  // tmptmp
  if (party == ALICE) {
    GMP_PRG_FP prgdelta;
    mpz_class delta = prgdelta.sample();

    Oprf<BoolIO<NetIO>> oprf(party, threads, ios);

    auto start = clock_start();

    oprf.setup(delta); 
    oprf.oprf_eval_server();   
    cout << delta << endl;

    double ttt = time_from(start);
    std::cout << "vole generation: " << ttt << " us" << std::endl; 
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
  } else {
    Oprf<BoolIO<NetIO>> oprf(party, threads, ios);

    auto start = clock_start();

    oprf.setup();
    mpz_class in = 2;
    mpz_class out = oprf.oprf_eval_client(in);
    cout << in << endl;
    cout << out << endl;

    double ttt = time_from(start);
    std::cout << "vole generation: " << ttt << " us" << std::endl;    
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
  }


  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}

