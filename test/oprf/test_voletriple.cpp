
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
            << "------------ TEST VOLETRIPLE ------------"
            << std::endl
            << std::endl;

  cout << "#VOLE: "; int test_nn = 10005354;

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);    

  // tmptmp
  if (party == ALICE) {
    GMP_PRG_FP prgdelta;
    mpz_class delta = prgdelta.sample();

    OprfVoleTriple<BoolIO<NetIO>> vole(party, threads, ios);

    auto start = clock_start();

    vole.setup(delta);    
    std::vector<mpz_class> vole_yz(test_nn);
    vole.extend_sender(&vole_yz[0], test_nn);

    double ttt = time_from(start);
    std::cout << "vole generation: " << ttt << " us" << std::endl; 
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;

    // checking the correctness
    std::cout << "starting correctness testing..." << std::endl;
    std::vector<uint8_t> ext(48);
    hex_decompose(delta, &ext[0]);
    ios[0]->send_data(&ext[0], 48);
    ios[0]->flush();

    for (int i = 0; i < test_nn; i++) {
        for (int j = 0; j < 48; j++) ext[j] = 0;
        hex_decompose(vole_yz[i], &ext[0]);
        ios[0]->send_data(&ext[0], 48);
        ios[0]->flush();
    }
  } else {
    OprfVoleTriple<BoolIO<NetIO>> vole(party, threads, ios);

    auto start = clock_start();

    vole.setup();    
    std::vector<mpz_class> vole_yz(test_nn);
    std::vector<mpz_class> vole_x(test_nn);
    vole.extend_recver(&vole_yz[0], &vole_x[0], test_nn);

    double ttt = time_from(start);
    std::cout << "vole generation: " << ttt << " us" << std::endl;    
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;

    // checking the correctness
    std::cout << "starting correctness testing..." << std::endl;
    std::vector<uint8_t> ext(48);
    ios[0]->recv_data(&ext[0], 48);
    mpz_class delta = hex_compose(&ext[0]);

    for (int i = 0; i < test_nn; i++) {
        ios[0]->recv_data(&ext[0], 48);
        mpz_class mac = hex_compose(&ext[0]);
        if ((delta * vole_x[i] + mac) % gmp_P != vole_yz[i]) {
            std::cout << "check fail! " << i << std::endl;
            cout << delta << ' ' << vole_x[i] << ' ' << mac << ' ' << vole_yz[i] << endl;
            abort();
        }
    }
    std::cout << "check pass" << std::endl;
  }


  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}

