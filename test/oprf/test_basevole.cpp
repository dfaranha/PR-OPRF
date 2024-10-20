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
        new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i + 1),
        party == ALICE);

  osuCrypto::Socket sock;
  if (party == ALICE) {
    sock = osuCrypto::cp::asioConnect("127.0.0.1:"+string(argv[2]), true);
  } else {
    sock = osuCrypto::cp::asioConnect("127.0.0.1:"+string(argv[2]), false);
  }        

  std::cout << std::endl
            << "------------ TEST BASEVOLE ------------"
            << std::endl
            << std::endl;

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);  

  // tmptmp
  if (party == ALICE) {
    GMP_PRG_FP prgdelta;
    mpz_class delta; // = prgdelta.sample();

    OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], delta, sock);

    std::vector<mpz_class> v(50000);
    auto start = clock_start();
    basevole.triple_gen_send(v, 50000);
    double ttt = time_from(start);
    std::cout << "base VOLE generation: " << ttt << " us" << std::endl; 
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl;    
  } else {
    OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], sock);

    std::vector<mpz_class> u(50000);
    std::vector<mpz_class> w(50000);
    auto start = clock_start();
    basevole.triple_gen_recv(w, u, 50000);
    double ttt = time_from(start);
    std::cout << "base VOLE generation: " << ttt << " us" << std::endl;    
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl;    
  }


  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}

