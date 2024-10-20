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
            << "------------ TEST MPFSS ------------"
            << std::endl
            << std::endl;

  int t = 20;
  int h = 9;
  int leave_n = 1 << h;
  int total_n = leave_n * t;

  uint64_t com1, com11;
  com1 = comm(ios);
  com11 = comm2(ios);    

  // tmptmp
  if (party == ALICE) {
    ThreadPool* pool = new ThreadPool(threads);
    std::vector<mpz_class> last(total_n);

    GMP_PRG_FP prgdelta;
    mpz_class delta; // = prgdelta.sample();

    OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], delta, sock);
    OprfMpfssRegFp<BoolIO<NetIO>> mpfss(party, threads, total_n, t, h, pool, ios);
    mpfss.set_malicious();
    //BaseCot<BoolIO<NetIO>> cot(party, ios[0], true);
    //cot.cot_gen_pre();

    auto start = clock_start();

    LibOTPre<BoolIO<NetIO>> *pre_ot = new LibOTPre<BoolIO<NetIO>>(ios[0], h, t);
    pre_ot->send_gen_pre(sock);
    pre_ot->send_gen(sock);
    //cot.cot_gen(pre_ot, pre_ot->n);

    std::vector<mpz_class> v(t+1);
    basevole.triple_gen_send(v, t+1);

    __uint128_t *ggm_tree_mem = new __uint128_t[total_n];

    mpfss.sender_init(delta);
    mpfss.mpfss(pre_ot, &v[0], ggm_tree_mem, &last[0]);

    double ttt = time_from(start);
    std::cout << "spsfss generation: " << ttt << " us" << std::endl; 
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl; 

    mpfss.check_correctness_sender(ios[0]);

    delete[] ggm_tree_mem;
    delete pool;
  } else {
    ThreadPool* pool = new ThreadPool(threads);
    std::vector<mpz_class> last(total_n);    

    OprfBaseVole<BoolIO<NetIO>> basevole(party, ios[0], sock);
    OprfMpfssRegFp<BoolIO<NetIO>> mpfss(party, threads, total_n, t, h, pool, ios);
    mpfss.set_malicious();
    //BaseCot<BoolIO<NetIO>> cot(party, ios[0], true);
    //cot.cot_gen_pre();
    
    auto start = clock_start();

    LibOTPre<BoolIO<NetIO>> *pre_ot = new LibOTPre<BoolIO<NetIO>>(ios[0], h, t);
    pre_ot->recv_gen_pre(sock);
    pre_ot->recv_gen(sock);
    //cot.cot_gen(pre_ot, pre_ot->n);

    std::vector<mpz_class> w(t+1);
    std::vector<mpz_class> u(t+1);    
    basevole.triple_gen_recv(w, u, t+1);

    __uint128_t *ggm_tree_mem = new __uint128_t[total_n];

    mpfss.recver_init();
    mpfss.mpfss(pre_ot, &w[0], ggm_tree_mem, &last[0], &u[0]);

    double ttt = time_from(start);
    std::cout << "spsfss generation: " << ttt << " us" << std::endl;    
    uint64_t com2 = comm(ios) - com1;
    uint64_t com22 = comm2(ios) - com11;
    std::cout << "communication (B): " << com2 << std::endl;
    std::cout << "communication (B): " << com22 << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl; 

    mpfss.check_correctness_recver(ios[0], &u[0]);

    delete[] ggm_tree_mem;
    delete pool;
  }


  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}

