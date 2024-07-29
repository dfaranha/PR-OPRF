
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
  gmp_setup();
  auto start = clock_start();
  for (int i = 0; i < 1000000; i++) {
    mpz_class x = gmp_P - 10;
    mpz_class y = gmp_raise(x);    
  }
  cout << gmp_raise(gmp_P - 10) << endl;
  double ttt = time_from(start);
  std::cout << "pow time: " << ttt << " us" << std::endl;  
  return 0;
}

