
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
    sock = osuCrypto::cp::asioConnect("127.0.0.1:"+string(argv[2]), true);
  } else {
    sock = osuCrypto::cp::asioConnect(string(argv[3])+":"+string(argv[2]), false);
  }     

  std::cout << std::endl
            << "------------ TEST SEMI-HONEST OPRF ------------"
            << std::endl
            << std::endl;

  // cout << "#VOLE: "; int test_nn = 10005354;
  int test_nn = 10005354;

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);    

  // tmptmp
  if (party == ALICE) {
    GMP_PRG_FP prgdelta;
    mpz_class delta; // = prgdelta.sample();

    OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], delta, sock);

    std::vector<mpz_class> v(1);
    auto start = clock_start();
    basevole.triple_gen_send(v, 1);

    // oprf
    std::vector<uint8_t> ext(48);
    ios[0]->recv_data(&ext[0], 48);
    mpz_class msg1 = hex_compose(&ext[0]);
    mpz_class msg2 = ((msg1 - v[0]) % gmp_P + gmp_P) % gmp_P;
    GMP_PRG_FP prg;
    mpz_class alphae = prg.sample();    
    for (int i = 0; i < 128; i++) alphae = (alphae * alphae) % gmp_P;
    msg2 = (msg2 * alphae) % gmp_P;
    for (int i = 0; i < 48; i++) ext[i] = 0;
    hex_decompose(msg2, &ext[0]);
    ios[0]->send_data(&ext[0], 48);
    ios[0]->flush();    

    double ttt = time_from(start);
    std::cout << "base VOLE generation: " << ttt << " us" << std::endl; 
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl;    
  } else {
    OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], sock);

    std::vector<mpz_class> u(1);
    std::vector<mpz_class> w(1);
    auto start = clock_start();
    basevole.triple_gen_recv(w, u, 1);
    
    // oprf
    mpz_class x = 123;
    mpz_class msg1 = (w[0] * x + u[0]) % gmp_P;
    std::vector<uint8_t> ext(48);
    hex_decompose(msg1, &ext[0]);
    ios[0]->send_data(&ext[0], 48);
    ios[0]->flush();
    ios[0]->recv_data(&ext[0], 48);
    mpz_class msg2 = hex_compose(&ext[0]);
    mpz_class ans = gmp_raise(msg2 * gmp_inverse(w[0]) % gmp_P);    

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

