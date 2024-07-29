#ifndef _GMP_OPRF_
#define _GMP_OPRF_

#include "oprf/oprf.h"
#include "emp-tool/emp-tool.h"

template <typename IO> class Oprf {
public:
  IO *io;
  IO **ios;
  int party;
  int threads;
  mpz_class Delta;
  mpz_class zkDelta;
  OprfVoleTriple<IO> vole;
  OprfVoleTriple<IO> zkvole;

  mpz_class mac_oprf_key;
  std::vector<mpz_class> oprf_mac, oprf_a;
  std::vector<mpz_class> zk_mac;
  int cur;

  bool is_malicious = false;

  Oprf(int party, int threads, IO **ios) : vole(party, threads, ios), zkvole(3-party, threads, ios) {
    this->io = ios[0];
    this->ios = ios;
    this->party = party;
    this->threads = threads;

    gmp_setup();
  }

  void setup(mpz_class delta) {
    this->Delta = delta;
    vole.setup(delta);
  }

  void setup() {
    vole.setup();
  }

  // setup the inverse direction vole for zk
  // ask the server to commit to the oprf key Delta
  void setup_malicious() {
    is_malicious = true;
    if (party == ALICE) {
      zkvole.setup();
      mpz_class x;
      zkvole.extend_recver(&mac_oprf_key, &x, 1);
      std::vector<uint8_t> ext(48);
      x = (Delta + gmp_P - x) % gmp_P;
      hex_decompose(x, &ext[0]);
      io->send_data(&ext[0], 48);
      io->flush();
    } else {
      GMP_PRG_FP keyprg;
      zkDelta = keyprg.sample();
      zkvole.setup(zkDelta);
      zkvole.extend_sender(&mac_oprf_key, 1);
      std::vector<uint8_t> ext(48);
      io->recv_data(&ext[0], 48);
      mac_oprf_key = (mac_oprf_key + (gmp_P - (hex_compose(&ext[0]) * zkDelta % gmp_P))) % gmp_P;
    }
  }

  void malicious_offline(int sz) {
    cur = 0;
    oprf_mac.resize(sz);
    zk_mac.resize(sz);    
    if (party == ALICE) {
      std::vector<mpz_class> tmp_r(sz);
      mpz_class mask_oprf_mac;
      mpz_class mask_zk_mac, mask_tmp_r;

      // generate oprf-vole related correlations
      vole.extend_sender(&oprf_mac[0], sz);
      vole.extend_sender(&mask_oprf_mac, 1);

      // generate zk-vole related correlations
      zkvole.extend_recver(&zk_mac[0], &tmp_r[0], sz);
      zkvole.extend_recver(&mask_zk_mac, &mask_tmp_r, 1);

      // the servers need to commit to the shares
      std::vector<uint8_t> ext(48 * (sz + 1));
      for (int i = 0; i < sz; i++) {
        tmp_r[i] = (oprf_mac[i] + gmp_P - tmp_r[i]) % gmp_P;
        hex_decompose(tmp_r[i], &ext[48 * i]);
      }
      mask_tmp_r = (mask_oprf_mac + gmp_P - mask_tmp_r) % gmp_P;
      hex_decompose(mask_tmp_r, &ext[48 * sz]);
      io->send_data(&ext[0], 48 * (sz + 1));
      io->flush();

      // universal linear hashing check 
      io->recv_data(&ext[0], 96);
      mpz_class chi = hex_compose(&ext[0]);
      mpz_class acc_oprf_a = hex_compose(&ext[48]);
      mpz_class acc_zk_mac = mask_zk_mac;
      mpz_class powchi = chi;
      for (int i = 0; i < sz; i++) {
        acc_zk_mac = (acc_zk_mac + powchi * zk_mac[i]) % gmp_P;
        powchi = powchi * chi % gmp_P;
      }
      mpz_class proof_pi = (acc_zk_mac + acc_oprf_a * mac_oprf_key) % gmp_P;
      //cout << proof_pi << endl;
      for (int i = 0; i < 48; i++) ext[i] = 0;
      hex_decompose(proof_pi, &ext[0]);
      io->send_data(&ext[0], 48);
      io->flush();
    } else {
      oprf_a.resize(sz); // only client needs to resize the "blinding" a's
      mpz_class mask_oprf_mac, mask_oprf_a;
      mpz_class mask_zk_mac;

      // generate oprf-vole related correlations
      vole.extend_recver(&oprf_mac[0], &oprf_a[0], sz);
      vole.extend_recver(&mask_oprf_mac, &mask_oprf_a, 1);

      // generate zk-vole related correlations
      zkvole.extend_sender(&zk_mac[0], sz);
      zkvole.extend_sender(&mask_zk_mac, 1);

      // the servers commit to its shares
      std::vector<uint8_t> ext(48 * (sz + 1));
      io->recv_data(&ext[0], 48 * (sz + 1));
      for (int i = 0; i < sz; i++)
        zk_mac[i] = (zk_mac[i] + (gmp_P - (hex_compose(&ext[i*48]) * zkDelta % gmp_P))) % gmp_P;
      mask_zk_mac = (mask_zk_mac + (gmp_P - (hex_compose(&ext[sz*48]) * zkDelta % gmp_P))) % gmp_P;

      // universal linear hashing check
      mpz_class chi = GMP_PRG_FP().sample();
      std::vector<mpz_class> powchi(sz);
      powchi[0] = chi;
      for (int i = 1; i < sz; i++) powchi[i] = powchi[i-1] * chi % gmp_P;
      // several accumulators      
      mpz_class acc_oprf_a = mask_oprf_a;
      for (int i = 0; i < sz; i++) acc_oprf_a = (acc_oprf_a + oprf_a[i] * powchi[i]) % gmp_P;
      for (int i = 0; i < 96; i++) ext[i] = 0;
      // TODO: check if it is okay to not send the "MAC" to ensure a correct acc_oprf_a (it should be)
      hex_decompose(chi, &ext[0]);
      hex_decompose(acc_oprf_a, &ext[48]);
      io->send_data(&ext[0], 96);
      io->flush();
      
      // delay this computation for better e2e time (i.e., p can start earlier)
      mpz_class acc_oprf_mac = mask_oprf_mac;
      mpz_class acc_zk_mac = mask_zk_mac;
      for (int i = 0; i < sz; i++) {
        acc_oprf_mac = (acc_oprf_mac + oprf_mac[i] * powchi[i]) % gmp_P;
        acc_zk_mac = (acc_zk_mac + zk_mac[i] * powchi[i]) % gmp_P;
      }

      mpz_class expect_pi = (acc_oprf_mac * zkDelta + acc_zk_mac + acc_oprf_a * mac_oprf_key) % gmp_P;
      //cout << expect_pi << endl;
      io->recv_data(&ext[0], 48);
      if (expect_pi != hex_compose(&ext[0])) {
        std::cout << "The server is cheating in the offline phase to prepare the commitments of shares!" << std::endl;
        abort();
      }      
    }

    cout << "shares committed!" << endl;

    // this comment code is used to check the correctness of committed shares
    // cout << "correctness checking..." << endl;
    // if (party == ALICE) {      
    //   for (int i = 0; i < sz; i++) {
    //     std::vector<uint8_t> ext(96);
    //     hex_decompose(oprf_mac[i], &ext[0]);
    //     hex_decompose(zk_mac[i], &ext[48]);
    //     io->send_data(&ext[0], 96);
    //     io->flush();
    //   }
    // } else {
    //   std::vector<uint8_t> ext(96);
    //   for (int i = 0; i < sz; i++) {
    //     io->recv_data(&ext[0], 96);
    //     mpz_class val = hex_compose(&ext[0]);
    //     mpz_class pi = hex_compose(&ext[48]);
    //     if ((val * zkDelta + zk_mac[i]) % gmp_P != pi) {
    //       cout << "error " << i << endl;
    //       abort();
    //     }
    //   }
    //   cout << "correctness check pass" << endl;
    // }

    // now, we need to prepare alpha^e
    

  }

  // single eval
  void oprf_eval_server() {
    std::vector<uint8_t> ext(48);
    mpz_class share;
    vole.extend_sender(&share, 1);
    io->recv_data(&ext[0], 48);
    mpz_class msg1 = hex_compose(&ext[0]);
    mpz_class msg2 = ((msg1 - share) % gmp_P + gmp_P) % gmp_P;
    GMP_PRG_FP prg;
    mpz_class alphae = prg.sample();
    for (int i = 0; i < 128; i++) alphae = (alphae * alphae) % gmp_P;
    msg2 = (msg2 * alphae) % gmp_P;
    for (int i = 0; i < 48; i++) ext[i] = 0;
    hex_decompose(msg2, &ext[0]);
    io->send_data(&ext[0], 48);
    io->flush();
  }

  mpz_class oprf_eval_client(const mpz_class &x) {
    std::vector<uint8_t> ext(48);
    mpz_class share, a;
    vole.extend_recver(&share, &a, 1);
    mpz_class msg1 = (a * x + share) % gmp_P;
    hex_decompose(msg1, &ext[0]);
    io->send_data(&ext[0], 48);
    io->flush();
    io->recv_data(&ext[0], 48);
    mpz_class msg2 = hex_compose(&ext[0]);

    return gmp_raise(msg2 * gmp_inverse(a) % gmp_P);
  }

  // batch eval
  void oprf_batch_eval_server(const int &sz) {
    std::vector<uint8_t> ext(48 * sz);
    std::vector<mpz_class> share(sz);
    vole.extend_sender(&share[0], sz);
    io->recv_data(&ext[0], 48 * sz);
    mpz_class msg1, msg2, alphae;
    GMP_PRG_FP prg;
    for (int i = 0; i < sz; i++) {
      msg1 = hex_compose(&ext[48 * i]);
      msg2 = ((msg1 - share[i]) % gmp_P + gmp_P) % gmp_P;
      alphae = prg.sample();
      for (int j = 0; j < 128; j++) alphae = (alphae * alphae) % gmp_P;
      msg2 = (msg2 * alphae) % gmp_P;
      for (int j = 48 * i; j < 48 * (i+1); j++) ext[j] = 0;
      hex_decompose(msg2, &ext[48 * i]);
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
  }

  void oprf_batch_eval_client(const mpz_class *x, const int &sz, std::vector<mpz_class> &y) {
    std::vector<uint8_t> ext(48 * sz);
    y.resize(sz);
    std::vector<mpz_class> share(sz), a(sz);
    vole.extend_recver(&share[0], &a[0], sz);
    mpz_class msg1;
    for (int i = 0; i < sz; i++) {
      msg1 = (a[i] * x[i] + share[i]) % gmp_P;
      hex_decompose(msg1, &ext[48 * i]);
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
    io->recv_data(&ext[0], 48 * sz);
    mpz_class msg2;
    for (int i = 0; i < sz; i++) {
      msg2 = hex_compose(&ext[48 * i]);
      y[i] = gmp_raise(msg2 * gmp_inverse(a[i]) % gmp_P);
    }
  }

};


#endif