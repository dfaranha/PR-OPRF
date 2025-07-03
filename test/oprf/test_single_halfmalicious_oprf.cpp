#define ENABLE_MALICIOUS // we have to do this to ahieve half-malicious
#define ENABLE_SS // enable SS VOLE

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
            << "------------ TEST NON-BATCHED HALF-MALICIOUS 2PC-GOLD ------------"
            << std::endl
            << std::endl;

  // cout << "#VOLE: "; int test_nn = 10005354;
  int test_nn = 1;

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);    
  com_main = com1;

  // tmptmp
  if (party == ALICE) {
    GMP_PRG_FP prgdelta;
    mpz_class delta; // = prgdelta.sample();

    Oprf<BoolIO<NetIO>> oprf(party, threads, ios, sock);

    auto start = clock_start();

#ifdef ENABLE_SS
    oprf.setup_base(delta, sock, false); 
#else
    oprf.setup_base(delta, sock); 
#endif
    double tts = time_from(start);
    start = clock_start();
    //oprf.oprf_eval_server();   
    oprf.oprf_batch_eval_server_base(test_nn, sock);

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

#ifdef ENABLE_SS
    oprf.setup_base(tmptmp, sock, false);
#else
    oprf.setup_base(tmptmp, sock); 
#endif
    double tts = time_from(start);
    std::vector<mpz_class> in(test_nn);
    for (int i = 0; i < test_nn; i++) in[i] = i;
    std::vector<mpz_class> out(test_nn);
    start = clock_start();
    oprf.oprf_batch_eval_client_base(&in[0], test_nn, out, sock);

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

  // tmptmp
  // if (party == ALICE) {
  //   GMP_PRG_FP prgdelta;
  //   mpz_class delta; // = prgdelta.sample();

  //   OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], delta, sock);

  //   std::vector<mpz_class> v(1);
  //   auto start = clock_start();
  //   basevole.triple_gen_send(v, 1);

  //   // oprf
  //   std::vector<uint8_t> ext(48);
  //   ios[0]->recv_data(&ext[0], 48);
  //   mpz_class msg1 = hex_compose(&ext[0]);
  //   mpz_class msg2 = ((msg1 - v[0]) % gmp_P + gmp_P) % gmp_P;
  //   GMP_PRG_FP prg;
  //   mpz_class alphae = prg.sample();    
  //   for (int i = 0; i < 128; i++) alphae = (alphae * alphae) % gmp_P;
  //   msg2 = (msg2 * alphae) % gmp_P;
  //   for (int i = 0; i < 48; i++) ext[i] = 0;
  //   hex_decompose(msg2, &ext[0]);
  //   ios[0]->send_data(&ext[0], 48);
  //   ios[0]->flush();    

  //   double ttt = time_from(start);
  //   std::cout << "base VOLE generation: " << ttt << " us" << std::endl; 
  //   uint64_t com2 = comm(ios) - com1;
  //   uint64_t com22 = comm2(ios) - com11;
  //   std::cout << "communication (B): " << com2 << std::endl;
  //   std::cout << "communication (B): " << com22 << std::endl;
  //   std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl;    
  // } else {
  //   OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], sock);

  //   std::vector<mpz_class> u(1);
  //   std::vector<mpz_class> w(1);
  //   auto start = clock_start();
  //   basevole.triple_gen_recv(w, u, 1);
    
  //   // oprf
  //   mpz_class x = 123;
  //   mpz_class msg1 = (w[0] * x + u[0]) % gmp_P;
  //   std::vector<uint8_t> ext(48);
  //   hex_decompose(msg1, &ext[0]);
  //   ios[0]->send_data(&ext[0], 48);
  //   ios[0]->flush();
  //   ios[0]->recv_data(&ext[0], 48);
  //   mpz_class msg2 = hex_compose(&ext[0]);
  //   mpz_class ans = gmp_raise(msg2 * gmp_inverse(w[0]) % gmp_P);    

  //   double ttt = time_from(start);
  //   std::cout << "base VOLE generation: " << ttt << " us" << std::endl;    
  //   uint64_t com2 = comm(ios) - com1;
  //   uint64_t com22 = comm2(ios) - com11;
  //   std::cout << "communication (B): " << com2 << std::endl;
  //   std::cout << "communication (B): " << com22 << std::endl;
  //   std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl;    
  // }



  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}

