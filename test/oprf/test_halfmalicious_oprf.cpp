#define ENABLE_MALICIOUS // we have to do this to ahieve half-malicious
//#define ENABLE_SMALLN // for small n testing

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
        new NetIO(party == ALICE ? nullptr : argv[3], port + i + 1),
        party == ALICE);

  osuCrypto::Socket sock;
  if (party == ALICE) {
    sock = osuCrypto::cp::asioConnect(string(argv[3])+":"+string(argv[2]), true);
  } else {
    sock = osuCrypto::cp::asioConnect(string(argv[3])+":"+string(argv[2]), false);
  }             

  std::cout << std::endl
            << "------------ TEST BATCHED HALF-MALICIOUS 2PC-GOLD ------------"
            << std::endl
            << std::endl;

  // cout << "#VOLE: "; 
#ifndef ENABLE_SMALLN  
  int test_nn = 10005354;
#else
  int test_nn = 100000;
#endif

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);    

  // tmptmp
  if (party == ALICE) {
    GMP_PRG_FP prgdelta;
    mpz_class delta; // = prgdelta.sample();

    Oprf<BoolIO<NetIO>> oprf(party, threads, ios, sock);

    auto start = clock_start();

    oprf.setup(delta, sock); 
    double tts = time_from(start);
    //oprf.oprf_eval_server();   
    oprf.oprf_batch_eval_server(test_nn, sock);

    double ttt = time_from(start);
    std::cout << "oprf setup: " << tts << " us" << std::endl;
    std::cout << "oprf eval: " << ttt << " us" << std::endl; 
    uint64_t com2 = comm(ios) - com1;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesSent() << std::endl; 

    std::cout << "correctness checking..." << std::endl;
    std::vector<uint8_t> ext(48);
    hex_decompose(delta, &ext[0]);
    ios[0]->send_data(&ext[0], 48);
    ios[0]->flush();
  } else {
    mpz_class tmptmp;
    Oprf<BoolIO<NetIO>> oprf(party, threads, ios, sock);

    auto start = clock_start();

    oprf.setup(tmptmp, sock);
    double tts = time_from(start);
    std::vector<mpz_class> in(test_nn);
    for (int i = 0; i < test_nn; i++) in[i] = i;
    std::vector<mpz_class> out(test_nn);
    oprf.oprf_batch_eval_client(&in[0], test_nn, out, sock);

    double ttt = time_from(start);
    std::cout << "oprf setup: " << tts << " us" << std::endl;
    std::cout << "oprf eval: " << ttt << " us" << std::endl;    
    uint64_t com2 = comm(ios) - com1;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesSent() << std::endl; 

    std::cout << "correctness checking..." << std::endl;
    std::vector<uint8_t> ext(48);
    ios[0]->recv_data(&ext[0], 48);
    mpz_class delta = hex_compose(&ext[0]);

    for (int i = 0; i < test_nn; i++) {
      mpz_class ini = (in[i] + delta) % gmp_P;
      if (gmp_raise(ini) != out[i]) {
        cout << "wrong answer!" << endl;
        cout << i << ' ' << delta << ' ' << in[i] << ' ' << out[i] << endl;
        abort();
      }
    }
    cout << "check pass" << endl;
  }


  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}

