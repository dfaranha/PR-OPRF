#include <gmpxx.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include "oprf/oprf.h"

using namespace std;

int main() {
    mpz_class a, b, c;
    mpz_class x=4444;
    mpz_class y=123;
    mpz_class z("1234");
    cout << x*y << endl;
    cout << x%y << endl;
    cout << (x>=y) << endl;
    cout << z << endl;
    cout << gmp_P << endl;
    a = "1231249192412094124891204812941247129471204712947109241";
    b = "12381294102412666643625525325653263526112312312312";
    c = a%b;
    cout << "product is " << c << "\n";
    cout << "absolute value is " << abs(c) << "\n";
    return 0;
}