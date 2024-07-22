#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include "oprf/oprf.h"
#include <iostream>
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
            << "------------ try pr oprf ------------"
            << std::endl
            << std::endl;

  // tmptmp
  OprfMod.print();
  OprfFp xxx(0, 10, 0);

  OprfFp a(makeBlock(13835058055282163712ULL, 0ULL), makeBlock(0ULL, 0ULL), makeBlock(0ULL, 0ULL));
  OprfFp b(makeBlock(13835058055282163712ULL, 0ULL), makeBlock(0ULL, 0ULL), makeBlock(0ULL, 0ULL));
  OprfFp c;
  OprfFpAddMod(a, b, c);
  c.print();

  for (int i = 0; i < threads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}
