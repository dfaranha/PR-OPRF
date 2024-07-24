#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/emp-zk-arith.h"
#include "oprf/oprf.h"
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

int main(int argc, char **argv) {
  mpz_class num("500");
  std::vector<uint8_t> x(48);
  mpz_export(&x[0], NULL, -1, 1, 0, 0, num.get_mpz_t());
  cout << (int)x[0] << ' ' << (int)x[1] << ' ' << (int)x[2] << ' ' << (int)x[3] << endl;
  cout << num << endl;
  mpz_class num2;
  mpz_import(num2.get_mpz_t(), 48, -1, 1, 0, 0, &x[0]);
  cout << num2 << endl;
  return 0;
}
