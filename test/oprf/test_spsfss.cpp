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
    sock = osuCrypto::cp::asioConnect(string(argv[3])+":"+string(argv[2]), false);
  }     

  std::cout << std::endl
            << "------------ TEST SPSFSS ------------"
            << std::endl
            << std::endl;

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);  

  // tmptmp
  if (party == ALICE) {
    std::vector<mpz_class> last(1<<9);

    GMP_PRG_FP prgdelta;
    mpz_class delta; // = prgdelta.sample();

    OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], delta, sock);
    OprfSpfssSenderFp<BoolIO<NetIO>> spfss(ios[0], 10);
    //BaseCot<BoolIO<NetIO>> cot(party, ios[0], true);
    //cot.cot_gen_pre();
    
    auto start = clock_start();

    LibOTPre<BoolIO<NetIO>> *pre_ot = new LibOTPre<BoolIO<NetIO>>(ios[0], 9, 1);
    pre_ot->send_gen_pre(sock);
    pre_ot->send_gen(sock);

    //cot.cot_gen(pre_ot, pre_ot->n);
    pre_ot->choices_sender();

    std::vector<mpz_class> v(1);
    basevole.triple_gen_send(v, 1);
    __uint128_t *ggm_tree_mem = new __uint128_t[1 << 9];
    spfss.compute(ggm_tree_mem, &last[0], delta, v[0]);
    spfss.template send<LibOTPre<BoolIO<NetIO>>>(pre_ot, ios[0], 0);

    double ttt = time_from(start);
    std::cout << "spsfss generation: " << ttt << " us" << std::endl; 
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl; 

    spfss.correctness_check(ios[0]);    

    delete[] ggm_tree_mem;
  } else {
    std::vector<mpz_class> last(1<<9);
    OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], sock);
    OprfSpfssRecverFp<BoolIO<NetIO>> spfss(ios[0], 10);
    //BaseCot<BoolIO<NetIO>> cot(party, ios[0], true);
    //cot.cot_gen_pre();
    
    auto start = clock_start();

    LibOTPre<BoolIO<NetIO>> *pre_ot = new LibOTPre<BoolIO<NetIO>>(ios[0], 9, 1);
    pre_ot->recv_gen_pre(sock);
    pre_ot->recv_gen(sock);

    //cot.cot_gen(pre_ot, pre_ot->n);
    pre_ot->choices_recver(spfss.b);
    cout << "ID is " << spfss.get_index() << endl;

    std::vector<mpz_class> u(1);
    std::vector<mpz_class> w(1);
    basevole.triple_gen_recv(w, u, 1);

    spfss.template recv<LibOTPre<BoolIO<NetIO>>>(pre_ot, ios[0], 0);
    __uint128_t *ggm_tree_mem = new __uint128_t[1<<9];
    spfss.compute(ggm_tree_mem, &last[0], w[0]);

    double ttt = time_from(start);
    std::cout << "spsfss generation: " << ttt << " us" << std::endl;    
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl; 

    spfss.correctness_check(ios[0], u[0]);

    delete[] ggm_tree_mem;
  }


  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}

