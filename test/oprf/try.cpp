#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include "oprf/oprf.h"
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

int main(int argc, char **argv) {
  mpz_class xxx = gmp_P;
  std::cout << sizeof(xxx) << std::endl;
  xxx = mpz_class("999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999");
  std::cout << sizeof(xxx) << std::endl;
  return 0;
}
