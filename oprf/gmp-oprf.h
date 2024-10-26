#ifndef _GMP_OPRF_
#define _GMP_OPRF_

#include "oprf/oprf.h"
#include "emp-tool/emp-tool.h"

uint64_t com_main;
uint64_t com_test(BoolIO<NetIO> *ios[1]) {
	uint64_t c = 0;
	for(int i = 0; i < 1; ++i)
		c += ios[i]->io->counter;
	return c;
}

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

  std::unique_ptr<OprfBaseVole<IO>> basevole = nullptr;
  std::unique_ptr<OprfBaseVole<IO>> basezkvole = nullptr;
  std::unique_ptr<SoftSpokenOprfBaseVole<IO>> basevole2 = nullptr;
  std::unique_ptr<SoftSpokenOprfBaseVole<IO>> basezkvole2 = nullptr;  

  mpz_class mac_oprf_key;
  std::vector<mpz_class> oprf_mac, oprf_a;
  std::vector<mpz_class> zk_mac;
  std::vector<mpz_class> alpha, alpha_mac;
  int cur;
  int epsilon; // optimization parameter

  bool is_malicious = false;

  Oprf(int party, int threads, IO **ios, int epsilon = 4) : vole(party, threads, ios), zkvole(3-party, threads, ios) {
    if (128 % epsilon != 0 || epsilon > 16) {
      cout << "invalid epsilon!" << endl;
      abort();
    }
    this->epsilon = epsilon;    
    this->io = ios[0];
    this->ios = ios;
    this->party = party;
    this->threads = threads;

    // gmp_setup();
    generate_coeff(epsilon); // this is only useful for the malicious case
  }

  Oprf(int party, int threads, IO **ios, osuCrypto::Socket &sock,int epsilon = 4) : vole(party, threads, ios, sock), zkvole(3-party, threads, ios, sock) {
    if (128 % epsilon != 0 || epsilon > 16) {
      cout << "invalid epsilon!" << endl;
      abort();
    }
    this->epsilon = epsilon;    
    this->io = ios[0];
    this->ios = ios;
    this->party = party;
    this->threads = threads;

    // gmp_setup();
    generate_coeff(epsilon); // this is only useful for the malicious case
  }

  void setup(mpz_class delta) {
    this->Delta = delta;
    vole.setup(delta);
  }

  void setup() {
    vole.setup();
  }

  // setup with libOTe
  void setup(mpz_class &delta, osuCrypto::Socket &sock) {
    vole.setup(delta, sock);
    this->Delta = delta;
  }

  // setup with libOTe and BaseVole
  void setup_base(mpz_class &delta, osuCrypto::Socket &sock) {
    if (party == ALICE) {
      basevole = std::make_unique<OprfBaseVole<IO>>(party, ios[0], delta, sock, false);
      this->Delta = delta;
    } else {
      basevole = std::make_unique<OprfBaseVole<IO>>(party, ios[0], sock, false);
    }
  }

  // setup with libOTe and BaseVole
  void setup_base(mpz_class &delta, osuCrypto::Socket &sock, const bool mali) {

    if (party == ALICE) {
      basevole2 = std::make_unique<SoftSpokenOprfBaseVole<IO>>(party, ios[0]);

      BaseOTType bot;
      osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

      // setup base OTs
      coproto::sync_wait(bot.send(saved_sMsgs, prng, sock));
      coproto::sync_wait(sock.flush());

      if (mali) basevole2->receiver_prepare_mali(2, sock);
      else basevole2->receiver_prepare(1, sock);

      this->Delta = basevole2->Delta;
      delta = this->Delta;
    } else {
      basevole2 = std::make_unique<SoftSpokenOprfBaseVole<IO>>(party, ios[0]);

      BaseOTType bot;
      osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

      // setup base OTs
      saved_choices.randomize(prng);
      coproto::sync_wait(bot.receive(saved_choices, saved_rMsgs, prng, sock));
      coproto::sync_wait(sock.flush());

      if (mali) basevole2->sender_prepare_mali(2, sock);
      else basevole2->sender_prepare(1, sock);
    }

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

  // setup the inverse direction vole for zk
  // ask the server to commit to the oprf key Delta
  // with libOTe
  void setup_malicious(osuCrypto::Socket &sock) {
    is_malicious = true;
    if (party == ALICE) {
      zkvole.setup(zkDelta, sock);
      mpz_class x;
      zkvole.extend_recver(sock, &mac_oprf_key, &x, 1);
      std::vector<uint8_t> ext(48);
      x = (Delta + gmp_P - x) % gmp_P;
      hex_decompose(x, &ext[0]);
      io->send_data(&ext[0], 48);
      io->flush();
    } else {
      //GMP_PRG_FP keyprg;
      //zkDelta = keyprg.sample();
      zkvole.setup(zkDelta, sock);
      zkvole.extend_sender(sock, &mac_oprf_key, 1);
      std::vector<uint8_t> ext(48);
      io->recv_data(&ext[0], 48);
      mac_oprf_key = (mac_oprf_key + (gmp_P - (hex_compose(&ext[0]) * zkDelta % gmp_P))) % gmp_P;
    }
  }  

  // setup the inverse direction vole for zk
  // ask the server to commit to the oprf key Delta
  // with libOTe // and base for single eval
  void setup_malicious_base(osuCrypto::Socket &sock) {
    is_malicious = true;
    auto desired_size = 128/epsilon + (1<<epsilon) + 4;
    if (party == ALICE) {
      std::vector<mpz_class> x(1);
      std::vector<mpz_class> w(1);

      // basezkvole = std::make_unique<OprfBaseVole<IO>>(3-party, ios[0], sock, true);
      // basezkvole->triple_gen_recv(w, x, 1);

      basezkvole2 = std::make_unique<SoftSpokenOprfBaseVole<IO>>(3-party, ios[0]);
      basezkvole2->sender_prepare(desired_size, sock);
      basezkvole2->triple_gen_recv(w, x, 1);

      mac_oprf_key = w[0];
      std::vector<uint8_t> ext(48);
      x[0] = (Delta + gmp_P - x[0]) % gmp_P;
      hex_decompose(x[0], &ext[0]);
      io->send_data(&ext[0], 48);
      io->flush();
    } else {
      std::vector<mpz_class> v(1);

      // basezkvole = std::make_unique<OprfBaseVole<IO>>(3-party, ios[0], zkDelta, sock, true);
      // basezkvole->triple_gen_send(v, 1);
      // cout << v[0] << ' ' << basezkvole->Delta << endl;

      basezkvole2 = std::make_unique<SoftSpokenOprfBaseVole<IO>>(3-party, ios[0]);
      basezkvole2->receiver_prepare(desired_size, sock);
      basezkvole2->triple_gen_send(v, 1);   
      zkDelta = basezkvole2->Delta;   

      mac_oprf_key = v[0];
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

    // now, we need to prepare alpha^e (#total = sz)
    // std::vector<mpz_class> alpha, alpha_mac;    
    uint32_t coeff_cnt = 1 << epsilon;    
    int inter_cnt = 128 / epsilon;
    if (party == ALICE) {
      std::vector<mpz_class> r(sz * (inter_cnt + 1));
      std::vector<mpz_class> r_mac(sz * (inter_cnt + 1));
      zkvole.extend_recver(&r_mac[0], &r[0], sz * (inter_cnt + 1));

      // commit the intermedia value
      std::vector<uint8_t> diff(sz * inter_cnt * 48);
      for (int i = 0; i < sz; i++) {
        mpz_class cur_alpha = r[i * (inter_cnt + 1)];
        for (int j = 0; j < inter_cnt; j++) {
          //for (int t = 0; t < epsilon; t++) cur_alpha = (cur_alpha * cur_alpha) % gmp_P;
          mpz_class next_cur;
          mpz_powm_ui(next_cur.get_mpz_t(), cur_alpha.get_mpz_t(), coeff_cnt, gmp_P.get_mpz_t());
          cur_alpha = next_cur;
          hex_decompose( (cur_alpha + gmp_P - r[i * (inter_cnt + 1) + 1 + j]) % gmp_P, &diff[ (i * inter_cnt + j) * 48 ]);
          r[i * (inter_cnt + 1) + 1 + j] = cur_alpha;
        }
      }
      io->send_data(&diff[0], sz * inter_cnt * 48);
      io->flush();

      // lpzk polynomial proof
      std::vector<uint8_t> ext(48);
      io->recv_data(&ext[0], 48);
      mpz_class chi = hex_compose(&ext[0]);
      mpz_class powchi = chi;

      std::vector<mpz_class> pi_coeff(coeff_cnt);
      std::vector<mpz_class> A_pow(coeff_cnt);
      std::vector<mpz_class> B_pow(coeff_cnt+1);
      A_pow[0] = B_pow[0] = 1;

      for (int i = 0; i < sz; i++)
        for (int j = 0; j < inter_cnt; j++) {
          // r[i * (inter_cnt + 1) + j]^coeff_cnt = r[i * (inter_cnt + 1) + j + 1]
          mpz_class A = gmp_P - r[i * (inter_cnt + 1) + j];
          mpz_class B = r_mac[i * (inter_cnt + 1) + j];
          // (AX+B)^coeff_cnt
          for (int k = 1; k < coeff_cnt; k++) A_pow[k] = (A_pow[k-1] * A) % gmp_P;            
          for (int k = 1; k < coeff_cnt + 1; k++) B_pow[k] = (B_pow[k-1] * B) % gmp_P;
          // compute the coefficients
          for (int k = 0; k < coeff_cnt; k++) 
            pi_coeff[k] = (pi_coeff[k] + powchi * B_pow[coeff_cnt-k] * A_pow[k] * zk_coeff[k]) % gmp_P;
          pi_coeff[coeff_cnt-1] = (pi_coeff[coeff_cnt-1] + powchi * r_mac[i * (inter_cnt + 1) + j + 1]) % gmp_P;
          powchi = (powchi * chi) % gmp_P;
        }

      // adding ZK
      std::vector<mpz_class> otp_mac(coeff_cnt-1);
      std::vector<mpz_class> otp(coeff_cnt-1);
      zkvole.extend_recver(&otp_mac[0], &otp[0], coeff_cnt-1);
      for (int i = 0; i < coeff_cnt - 1; i++) {
        pi_coeff[i] = (pi_coeff[i] + otp_mac[i]) % gmp_P;
        pi_coeff[i+1] = (pi_coeff[i+1] + (gmp_P - otp[i])) % gmp_P;
      }

      std::vector<uint8_t> hex_pi_coeff(coeff_cnt * 48);
      for (int i = 0; i < coeff_cnt; i++) hex_decompose(pi_coeff[i], &hex_pi_coeff[i * 48]);
      io->send_data(&hex_pi_coeff[0], coeff_cnt * 48);
      io->flush();

      // extract out the desireed values
      alpha.resize(sz);
      alpha_mac.resize(sz);
      
      for (int i = 0; i < sz; i++) {
        alpha[i] = r[(i + 1) * (inter_cnt + 1) - 1];
        alpha_mac[i] = r_mac[(i + 1) * (inter_cnt + 1) - 1];
      }

    } else {
      std::vector<mpz_class> r_mac(sz * (inter_cnt + 1));
      zkvole.extend_sender(&r_mac[0], sz * (inter_cnt + 1));

      // commit the intermedia value
      std::vector<uint8_t> diff(sz * inter_cnt * 48);
      io->recv_data(&diff[0], sz * inter_cnt * 48);
      for (int i = 0; i < sz; i++) 
        for (int j = 0; j < inter_cnt; j++) 
          r_mac[i * (inter_cnt + 1) + 1 + j] = (r_mac[i * (inter_cnt + 1) + 1 + j] + (gmp_P - hex_compose( &diff[ (i * inter_cnt + j) * 48 ] ) * zkDelta % gmp_P ) ) % gmp_P;

      // lpzk polynomial proof
      std::vector<uint8_t> ext(48);
      mpz_class chi = GMP_PRG_FP().sample();
      hex_decompose(chi, &ext[0]);
      io->send_data(&ext[0], 48);
      io->flush();
      mpz_class powchi = chi;

      mpz_class expect_pi = 0;
      std::vector<mpz_class> powdelta(coeff_cnt); powdelta[0] = 1;
      for (int i = 1; i < coeff_cnt; i++) powdelta[i] = (powdelta[i-1] * zkDelta) % gmp_P;
      for (int i = 0; i < sz; i++)
        for (int j = 0; j < inter_cnt; j++) {
          // r[i * (inter_cnt + 1) + j]^coeff_cnt = r[i * (inter_cnt + 1) + j + 1]
          mpz_class tmp_pi;
          mpz_powm_ui(tmp_pi.get_mpz_t(), r_mac[ i * (inter_cnt + 1) + j ].get_mpz_t(), coeff_cnt, gmp_P.get_mpz_t());
          tmp_pi = (tmp_pi + powdelta[coeff_cnt-1] * r_mac[ i * (inter_cnt + 1) + j + 1 ]) % gmp_P;
          expect_pi = (expect_pi + tmp_pi * powchi) % gmp_P;
          powchi = (powchi * chi) % gmp_P;
        }

      // adding zk
      std::vector<mpz_class> otp_mac(coeff_cnt-1);
      zkvole.extend_sender(&otp_mac[0], coeff_cnt-1);
      for (int i = 0; i < coeff_cnt-1; i++) expect_pi = (expect_pi + otp_mac[i] * powdelta[i]) % gmp_P;

      std::vector<uint8_t> hex_pi_coeff(coeff_cnt * 48);
      io->recv_data(&hex_pi_coeff[0], coeff_cnt * 48);
      mpz_class server_pi;
      for (int i = 0; i < coeff_cnt; i++) server_pi = (server_pi + powdelta[i] * hex_compose(&hex_pi_coeff[i * 48])) % gmp_P;

      if (server_pi != expect_pi) {
        std::cout << "The server is cheating in the offline phase to prepare the e-th residues!" << std::endl;
        abort();
      }
      std::cout << "e-th residues prepared!" << std::endl;

      // extract out the desired values
      alpha_mac.resize(sz);

      for (int i = 0; i < sz; i++) 
        alpha_mac[i] = r_mac[(i + 1) * (inter_cnt + 1) - 1];

    }

    cout << zkvole.ot_limit << ' ' << zkvole.ot_used << endl;

  }

  // with libOTe
  void malicious_offline(int sz, osuCrypto::Socket &sock) {
    cur = 0;
    oprf_mac.resize(sz);
    zk_mac.resize(sz);    
    if (party == ALICE) {
      std::vector<mpz_class> tmp_r(sz);
      mpz_class mask_oprf_mac;
      mpz_class mask_zk_mac, mask_tmp_r;

      // generate oprf-vole related correlations
      vole.extend_sender(sock, &oprf_mac[0], sz);
      vole.extend_sender(sock, &mask_oprf_mac, 1);

      // generate zk-vole related correlations
      zkvole.extend_recver(sock, &zk_mac[0], &tmp_r[0], sz);
      zkvole.extend_recver(sock, &mask_zk_mac, &mask_tmp_r, 1);

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
      vole.extend_recver(sock, &oprf_mac[0], &oprf_a[0], sz);
      vole.extend_recver(sock, &mask_oprf_mac, &mask_oprf_a, 1);

      // generate zk-vole related correlations
      zkvole.extend_sender(sock, &zk_mac[0], sz);
      zkvole.extend_sender(sock, &mask_zk_mac, 1);

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

    // now, we need to prepare alpha^e (#total = sz)
    // std::vector<mpz_class> alpha, alpha_mac;    
    uint32_t coeff_cnt = 1 << epsilon;    
    int inter_cnt = 128 / epsilon;
    if (party == ALICE) {
      std::vector<mpz_class> r(sz * (inter_cnt + 1));
      std::vector<mpz_class> r_mac(sz * (inter_cnt + 1));
      zkvole.extend_recver(sock, &r_mac[0], &r[0], sz * (inter_cnt + 1));

      // commit the intermedia value
      std::vector<uint8_t> diff(sz * inter_cnt * 48);
      for (int i = 0; i < sz; i++) {
        mpz_class cur_alpha = r[i * (inter_cnt + 1)];
        for (int j = 0; j < inter_cnt; j++) {
          //for (int t = 0; t < epsilon; t++) cur_alpha = (cur_alpha * cur_alpha) % gmp_P;
          mpz_class next_cur;
          mpz_powm_ui(next_cur.get_mpz_t(), cur_alpha.get_mpz_t(), coeff_cnt, gmp_P.get_mpz_t());
          cur_alpha = next_cur;
          hex_decompose( (cur_alpha + gmp_P - r[i * (inter_cnt + 1) + 1 + j]) % gmp_P, &diff[ (i * inter_cnt + j) * 48 ]);
          r[i * (inter_cnt + 1) + 1 + j] = cur_alpha;
        }
      }
      io->send_data(&diff[0], sz * inter_cnt * 48);
      io->flush();

      // lpzk polynomial proof
      std::vector<uint8_t> ext(48);
      io->recv_data(&ext[0], 48);
      mpz_class chi = hex_compose(&ext[0]);
      mpz_class powchi = chi;

      std::vector<mpz_class> pi_coeff(coeff_cnt);
      std::vector<mpz_class> A_pow(coeff_cnt);
      std::vector<mpz_class> B_pow(coeff_cnt+1);
      A_pow[0] = B_pow[0] = 1;

      for (int i = 0; i < sz; i++)
        for (int j = 0; j < inter_cnt; j++) {
          // r[i * (inter_cnt + 1) + j]^coeff_cnt = r[i * (inter_cnt + 1) + j + 1]
          mpz_class A = gmp_P - r[i * (inter_cnt + 1) + j];
          mpz_class B = r_mac[i * (inter_cnt + 1) + j];
          // (AX+B)^coeff_cnt
          for (int k = 1; k < coeff_cnt; k++) A_pow[k] = (A_pow[k-1] * A) % gmp_P;            
          for (int k = 1; k < coeff_cnt + 1; k++) B_pow[k] = (B_pow[k-1] * B) % gmp_P;
          // compute the coefficients
          for (int k = 0; k < coeff_cnt; k++) 
            pi_coeff[k] = (pi_coeff[k] + powchi * B_pow[coeff_cnt-k] * A_pow[k] * zk_coeff[k]) % gmp_P;
          pi_coeff[coeff_cnt-1] = (pi_coeff[coeff_cnt-1] + powchi * r_mac[i * (inter_cnt + 1) + j + 1]) % gmp_P;
          powchi = (powchi * chi) % gmp_P;
        }

      // adding ZK
      std::vector<mpz_class> otp_mac(coeff_cnt-1);
      std::vector<mpz_class> otp(coeff_cnt-1);
      zkvole.extend_recver(sock, &otp_mac[0], &otp[0], coeff_cnt-1);
      for (int i = 0; i < coeff_cnt - 1; i++) {
        pi_coeff[i] = (pi_coeff[i] + otp_mac[i]) % gmp_P;
        pi_coeff[i+1] = (pi_coeff[i+1] + (gmp_P - otp[i])) % gmp_P;
      }

      std::vector<uint8_t> hex_pi_coeff(coeff_cnt * 48);
      for (int i = 0; i < coeff_cnt; i++) hex_decompose(pi_coeff[i], &hex_pi_coeff[i * 48]);
      io->send_data(&hex_pi_coeff[0], coeff_cnt * 48);
      io->flush();

      // extract out the desireed values
      alpha.resize(sz);
      alpha_mac.resize(sz);
      
      for (int i = 0; i < sz; i++) {
        alpha[i] = r[(i + 1) * (inter_cnt + 1) - 1];
        alpha_mac[i] = r_mac[(i + 1) * (inter_cnt + 1) - 1];
      }

    } else {
      std::vector<mpz_class> r_mac(sz * (inter_cnt + 1));
      zkvole.extend_sender(sock, &r_mac[0], sz * (inter_cnt + 1));

      // commit the intermedia value
      std::vector<uint8_t> diff(sz * inter_cnt * 48);
      io->recv_data(&diff[0], sz * inter_cnt * 48);
      for (int i = 0; i < sz; i++) 
        for (int j = 0; j < inter_cnt; j++) 
          r_mac[i * (inter_cnt + 1) + 1 + j] = (r_mac[i * (inter_cnt + 1) + 1 + j] + (gmp_P - hex_compose( &diff[ (i * inter_cnt + j) * 48 ] ) * zkDelta % gmp_P ) ) % gmp_P;

      // lpzk polynomial proof
      std::vector<uint8_t> ext(48);
      mpz_class chi = GMP_PRG_FP().sample();
      hex_decompose(chi, &ext[0]);
      io->send_data(&ext[0], 48);
      io->flush();
      mpz_class powchi = chi;

      mpz_class expect_pi = 0;
      std::vector<mpz_class> powdelta(coeff_cnt); powdelta[0] = 1;
      for (int i = 1; i < coeff_cnt; i++) powdelta[i] = (powdelta[i-1] * zkDelta) % gmp_P;
      for (int i = 0; i < sz; i++)
        for (int j = 0; j < inter_cnt; j++) {
          // r[i * (inter_cnt + 1) + j]^coeff_cnt = r[i * (inter_cnt + 1) + j + 1]
          mpz_class tmp_pi;
          mpz_powm_ui(tmp_pi.get_mpz_t(), r_mac[ i * (inter_cnt + 1) + j ].get_mpz_t(), coeff_cnt, gmp_P.get_mpz_t());
          tmp_pi = (tmp_pi + powdelta[coeff_cnt-1] * r_mac[ i * (inter_cnt + 1) + j + 1 ]) % gmp_P;
          expect_pi = (expect_pi + tmp_pi * powchi) % gmp_P;
          powchi = (powchi * chi) % gmp_P;
        }

      // adding zk
      std::vector<mpz_class> otp_mac(coeff_cnt-1);
      zkvole.extend_sender(sock, &otp_mac[0], coeff_cnt-1);
      for (int i = 0; i < coeff_cnt-1; i++) expect_pi = (expect_pi + otp_mac[i] * powdelta[i]) % gmp_P;

      std::vector<uint8_t> hex_pi_coeff(coeff_cnt * 48);
      io->recv_data(&hex_pi_coeff[0], coeff_cnt * 48);
      mpz_class server_pi;
      for (int i = 0; i < coeff_cnt; i++) server_pi = (server_pi + powdelta[i] * hex_compose(&hex_pi_coeff[i * 48])) % gmp_P;

      if (server_pi != expect_pi) {
        std::cout << "The server is cheating in the offline phase to prepare the e-th residues!" << std::endl;
        abort();
      }
      std::cout << "e-th residues prepared!" << std::endl;

      // extract out the desired values
      alpha_mac.resize(sz);

      for (int i = 0; i < sz; i++) 
        alpha_mac[i] = r_mac[(i + 1) * (inter_cnt + 1) - 1];

    }

    cout << zkvole.ot_limit << ' ' << zkvole.ot_used << endl;

  }  

  // with libOTe
  void malicious_offline_base(int sz, osuCrypto::Socket &sock) {

    uint32_t coeff_cnt = 1 << epsilon;    
    int inter_cnt = 128 / epsilon;    
    cur = 0;
    oprf_mac.resize(sz+1);
    zk_mac.resize(sz+1);    
    std::vector<mpz_class> tmp_r, r, r_mac, otp_mac, otp;

    // for testing VOLE hybrid
    if (party == ALICE) {
      tmp_r.resize(sz+1);
      //basevole->triple_gen_send(oprf_mac, sz+1);
      basevole2->triple_gen_send(oprf_mac, sz+1);
      //basezkvole->triple_gen_recv(zk_mac, tmp_r, sz+1);
      basezkvole2->triple_gen_recv(zk_mac, tmp_r, sz+1);
      r.resize(sz * (inter_cnt + 1));
      r_mac.resize(sz * (inter_cnt + 1));
      //basezkvole->triple_gen_recv(r_mac, r, sz * (inter_cnt + 1));
      basezkvole2->triple_gen_recv(r_mac, r, sz * (inter_cnt + 1));
      otp_mac.resize(coeff_cnt-1);
      otp.resize(coeff_cnt-1);      
      //basezkvole->triple_gen_recv(otp_mac, otp, coeff_cnt-1);
      basezkvole2->triple_gen_recv(otp_mac, otp, coeff_cnt-1);
      std::cout << 1+sz+1+sz*(inter_cnt + 1)+coeff_cnt-1 << std::endl;
    } else {
      oprf_a.resize(sz+1); // only client needs to resize the "blinding" a's
      //basevole->triple_gen_recv(oprf_mac, oprf_a, sz+1);
      basevole2->triple_gen_recv(oprf_mac, oprf_a, sz+1);
      //basezkvole->triple_gen_send(zk_mac, sz+1);
      basezkvole2->triple_gen_send(zk_mac, sz+1);
      r_mac.resize(sz * (inter_cnt + 1));
      //basezkvole->triple_gen_send(r_mac, sz * (inter_cnt + 1));
      basezkvole2->triple_gen_send(r_mac, sz * (inter_cnt + 1));
      otp_mac.resize(coeff_cnt-1);
      //basezkvole->triple_gen_send(otp_mac, coeff_cnt-1);
      basezkvole2->triple_gen_send(otp_mac, coeff_cnt-1);
    } 

    std::cout << "VOLE generations:" << std::endl;
    std::cout << "communication (B): " << com_test(ios)-com_main << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl;         

    if (party == ALICE) {      
      mpz_class mask_oprf_mac;
      mpz_class mask_zk_mac, mask_tmp_r;

      // generate oprf-vole related correlations
      // vole.extend_sender(sock, &oprf_mac[0], sz);
      // vole.extend_sender(sock, &mask_oprf_mac, 1);
      
      mask_oprf_mac = oprf_mac[sz];

      // generate zk-vole related correlations
      // zkvole.extend_recver(sock, &zk_mac[0], &tmp_r[0], sz);
      // zkvole.extend_recver(sock, &mask_zk_mac, &mask_tmp_r, 1);
      
      mask_zk_mac = zk_mac[sz];
      mask_tmp_r = tmp_r[sz];

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
      
      mpz_class mask_oprf_mac, mask_oprf_a;
      mpz_class mask_zk_mac;

      // generate oprf-vole related correlations
      // vole.extend_recver(sock, &oprf_mac[0], &oprf_a[0], sz);
      // vole.extend_recver(sock, &mask_oprf_mac, &mask_oprf_a, 1);
      
      mask_oprf_mac = oprf_mac[sz];
      mask_oprf_a = oprf_a[sz];

      // generate zk-vole related correlations
      // zkvole.extend_sender(sock, &zk_mac[0], sz);
      // zkvole.extend_sender(sock, &mask_zk_mac, 1);
      
      mask_zk_mac = zk_mac[sz];

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

    // now, we need to prepare alpha^e (#total = sz)
    // std::vector<mpz_class> alpha, alpha_mac;    
    if (party == ALICE) {      

      // commit the intermedia value
      std::vector<uint8_t> diff(sz * inter_cnt * 48);
      for (int i = 0; i < sz; i++) {
        mpz_class cur_alpha = r[i * (inter_cnt + 1)];
        for (int j = 0; j < inter_cnt; j++) {
          //for (int t = 0; t < epsilon; t++) cur_alpha = (cur_alpha * cur_alpha) % gmp_P;
          mpz_class next_cur;
          mpz_powm_ui(next_cur.get_mpz_t(), cur_alpha.get_mpz_t(), coeff_cnt, gmp_P.get_mpz_t());
          cur_alpha = next_cur;
          hex_decompose( (cur_alpha + gmp_P - r[i * (inter_cnt + 1) + 1 + j]) % gmp_P, &diff[ (i * inter_cnt + j) * 48 ]);
          r[i * (inter_cnt + 1) + 1 + j] = cur_alpha;
        }
      }
      io->send_data(&diff[0], sz * inter_cnt * 48);
      io->flush();

      // lpzk polynomial proof
      std::vector<uint8_t> ext(48);
      io->recv_data(&ext[0], 48);
      mpz_class chi = hex_compose(&ext[0]);
      mpz_class powchi = chi;

      std::vector<mpz_class> pi_coeff(coeff_cnt);
      std::vector<mpz_class> A_pow(coeff_cnt);
      std::vector<mpz_class> B_pow(coeff_cnt+1);
      A_pow[0] = B_pow[0] = 1;

      for (int i = 0; i < sz; i++)
        for (int j = 0; j < inter_cnt; j++) {
          // r[i * (inter_cnt + 1) + j]^coeff_cnt = r[i * (inter_cnt + 1) + j + 1]
          mpz_class A = gmp_P - r[i * (inter_cnt + 1) + j];
          mpz_class B = r_mac[i * (inter_cnt + 1) + j];
          // (AX+B)^coeff_cnt
          for (int k = 1; k < coeff_cnt; k++) A_pow[k] = (A_pow[k-1] * A) % gmp_P;            
          for (int k = 1; k < coeff_cnt + 1; k++) B_pow[k] = (B_pow[k-1] * B) % gmp_P;
          // compute the coefficients
          for (int k = 0; k < coeff_cnt; k++) 
            pi_coeff[k] = (pi_coeff[k] + powchi * B_pow[coeff_cnt-k] * A_pow[k] * zk_coeff[k]) % gmp_P;
          pi_coeff[coeff_cnt-1] = (pi_coeff[coeff_cnt-1] + powchi * r_mac[i * (inter_cnt + 1) + j + 1]) % gmp_P;
          powchi = (powchi * chi) % gmp_P;
        }

      // adding ZK
      
      for (int i = 0; i < coeff_cnt - 1; i++) {
        pi_coeff[i] = (pi_coeff[i] + otp_mac[i]) % gmp_P;
        pi_coeff[i+1] = (pi_coeff[i+1] + (gmp_P - otp[i])) % gmp_P;
      }

      std::vector<uint8_t> hex_pi_coeff(coeff_cnt * 48);
      for (int i = 0; i < coeff_cnt; i++) hex_decompose(pi_coeff[i], &hex_pi_coeff[i * 48]);
      io->send_data(&hex_pi_coeff[0], coeff_cnt * 48);
      io->flush();

      // extract out the desireed values
      alpha.resize(sz);
      alpha_mac.resize(sz);
      
      for (int i = 0; i < sz; i++) {
        alpha[i] = r[(i + 1) * (inter_cnt + 1) - 1];
        alpha_mac[i] = r_mac[(i + 1) * (inter_cnt + 1) - 1];
      }

    } else {
      
      // commit the intermedia value
      std::vector<uint8_t> diff(sz * inter_cnt * 48);
      io->recv_data(&diff[0], sz * inter_cnt * 48);
      for (int i = 0; i < sz; i++) 
        for (int j = 0; j < inter_cnt; j++) 
          r_mac[i * (inter_cnt + 1) + 1 + j] = (r_mac[i * (inter_cnt + 1) + 1 + j] + (gmp_P - hex_compose( &diff[ (i * inter_cnt + j) * 48 ] ) * zkDelta % gmp_P ) ) % gmp_P;

      // lpzk polynomial proof
      std::vector<uint8_t> ext(48);
      mpz_class chi = GMP_PRG_FP().sample();
      hex_decompose(chi, &ext[0]);
      io->send_data(&ext[0], 48);
      io->flush();
      mpz_class powchi = chi;

      mpz_class expect_pi = 0;
      std::vector<mpz_class> powdelta(coeff_cnt); powdelta[0] = 1;
      for (int i = 1; i < coeff_cnt; i++) powdelta[i] = (powdelta[i-1] * zkDelta) % gmp_P;
      for (int i = 0; i < sz; i++)
        for (int j = 0; j < inter_cnt; j++) {
          // r[i * (inter_cnt + 1) + j]^coeff_cnt = r[i * (inter_cnt + 1) + j + 1]
          mpz_class tmp_pi;
          mpz_powm_ui(tmp_pi.get_mpz_t(), r_mac[ i * (inter_cnt + 1) + j ].get_mpz_t(), coeff_cnt, gmp_P.get_mpz_t());
          tmp_pi = (tmp_pi + powdelta[coeff_cnt-1] * r_mac[ i * (inter_cnt + 1) + j + 1 ]) % gmp_P;
          expect_pi = (expect_pi + tmp_pi * powchi) % gmp_P;
          powchi = (powchi * chi) % gmp_P;
        }

      // adding zk
      for (int i = 0; i < coeff_cnt-1; i++) expect_pi = (expect_pi + otp_mac[i] * powdelta[i]) % gmp_P;

      std::vector<uint8_t> hex_pi_coeff(coeff_cnt * 48);
      io->recv_data(&hex_pi_coeff[0], coeff_cnt * 48);
      mpz_class server_pi;
      for (int i = 0; i < coeff_cnt; i++) server_pi = (server_pi + powdelta[i] * hex_compose(&hex_pi_coeff[i * 48])) % gmp_P;

      if (server_pi != expect_pi) {
        std::cout << "The server is cheating in the offline phase to prepare the e-th residues!" << std::endl;
        abort();
      }
      std::cout << "e-th residues prepared!" << std::endl;

      // extract out the desired values
      alpha_mac.resize(sz);

      for (int i = 0; i < sz; i++) 
        alpha_mac[i] = r_mac[(i + 1) * (inter_cnt + 1) - 1];

    }

    cout << zkvole.ot_limit << ' ' << zkvole.ot_used << endl;

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

  // batch malicious
  void oprf_batch_eval_server_malicious(const int &sz) {
    if (cur + sz > alpha.size()) malicious_offline(sz); // TODO: we can first use-up all the leftover correlations than extend
    std::vector<uint8_t> ext(48 * sz);
    io->recv_data(&ext[0], 48 * sz);
    std::vector<mpz_class> msg1(sz);
    std::vector<mpz_class> msg2(sz);
    for (int i = 0; i < sz; i++) {
      msg1[i] = hex_compose(&ext[48 * i]);
      msg2[i] = ((msg1[i] - oprf_mac[cur + i]) % gmp_P + gmp_P) % gmp_P;
      msg2[i] = (msg2[i] * alpha[cur + i]) % gmp_P;
      for (int j = 48 * i; j < 48 * (i+1); j++) ext[j] = 0;
      hex_decompose(msg2[i], &ext[48 * i]);      
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
    // TODO: add ZK to prevent malicious bahaviors
    io->recv_data(&ext[0], 48);
    mpz_class chi = hex_compose(&ext[0]);
    mpz_class powchi = 1;
    mpz_class C1, C0; // two coefficients as the proof
    for (int i = 0; i < sz; i++) {
      int now = cur + i;
      C1 = (C1 + powchi * (msg1[i] + gmp_P - oprf_mac[now]) * alpha_mac[now] + powchi * (gmp_P - alpha[now]) * zk_mac[now] ) % gmp_P;
      C0 = (C0 + powchi * zk_mac[now] * alpha_mac[now]) % gmp_P;
      powchi = (powchi * chi) % gmp_P;
    }
    // final zk padding
    mpz_class pad1, pad0;
    zkvole.extend_recver(&pad0, &pad1, 1);
    C1 = (C1 + gmp_P - pad1) % gmp_P;
    C0 = (C0 + pad0) % gmp_P;
    std::vector<uint8_t> hex_pi(96);
    hex_decompose(C1, &hex_pi[0]);
    hex_decompose(C0, &hex_pi[48]);
    io->send_data(&hex_pi[0], 96);
    io->flush();
    cur += sz;
  }

  // batch malicious
  // with libOTe
  void oprf_batch_eval_server_malicious(const int &sz, osuCrypto::Socket &sock) {
    if (cur + sz > alpha.size()) malicious_offline(sz, sock); // TODO: we can first use-up all the leftover correlations than extend
    std::vector<uint8_t> ext(48 * sz);
    io->recv_data(&ext[0], 48 * sz);
    std::vector<mpz_class> msg1(sz);
    std::vector<mpz_class> msg2(sz);
    for (int i = 0; i < sz; i++) {
      msg1[i] = hex_compose(&ext[48 * i]);
      msg2[i] = ((msg1[i] - oprf_mac[cur + i]) % gmp_P + gmp_P) % gmp_P;
      msg2[i] = (msg2[i] * alpha[cur + i]) % gmp_P;
      for (int j = 48 * i; j < 48 * (i+1); j++) ext[j] = 0;
      hex_decompose(msg2[i], &ext[48 * i]);      
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
    // TODO: add ZK to prevent malicious bahaviors
    io->recv_data(&ext[0], 48);
    mpz_class chi = hex_compose(&ext[0]);
    mpz_class powchi = 1;
    mpz_class C1, C0; // two coefficients as the proof
    for (int i = 0; i < sz; i++) {
      int now = cur + i;
      C1 = (C1 + powchi * (msg1[i] + gmp_P - oprf_mac[now]) * alpha_mac[now] + powchi * (gmp_P - alpha[now]) * zk_mac[now] ) % gmp_P;
      C0 = (C0 + powchi * zk_mac[now] * alpha_mac[now]) % gmp_P;
      powchi = (powchi * chi) % gmp_P;
    }
    // final zk padding
    mpz_class pad1, pad0;
    zkvole.extend_recver(sock, &pad0, &pad1, 1);
    C1 = (C1 + gmp_P - pad1) % gmp_P;
    C0 = (C0 + pad0) % gmp_P;
    std::vector<uint8_t> hex_pi(96);
    hex_decompose(C1, &hex_pi[0]);
    hex_decompose(C0, &hex_pi[48]);
    io->send_data(&hex_pi[0], 96);
    io->flush();
    cur += sz;
  }  

  // single malicious
  // with libOTe
  void oprf_batch_eval_server_malicious_base(const int &sz, osuCrypto::Socket &sock) {
    // final zk padding
    std::vector<mpz_class> pad1(1);
    std::vector<mpz_class> pad0(1);
    //basezkvole2->triple_gen_recv(pad0, pad1, 1);    
    basezkvole2->triple_gen_recv(pad0, pad1, 1);    
    if (cur + sz > alpha.size()) malicious_offline_base(sz, sock); // TODO: we can first use-up all the leftover correlations than extend
    std::vector<uint8_t> ext(48 * sz);
    io->recv_data(&ext[0], 48 * sz);
    std::vector<mpz_class> msg1(sz);
    std::vector<mpz_class> msg2(sz);
    for (int i = 0; i < sz; i++) {
      msg1[i] = hex_compose(&ext[48 * i]);
      msg2[i] = ((msg1[i] - oprf_mac[cur + i]) % gmp_P + gmp_P) % gmp_P;
      msg2[i] = (msg2[i] * alpha[cur + i]) % gmp_P;
      for (int j = 48 * i; j < 48 * (i+1); j++) ext[j] = 0;
      hex_decompose(msg2[i], &ext[48 * i]);      
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
    // TODO: add ZK to prevent malicious bahaviors
    io->recv_data(&ext[0], 48);
    mpz_class chi = hex_compose(&ext[0]);
    mpz_class powchi = 1;
    mpz_class C1, C0; // two coefficients as the proof
    for (int i = 0; i < sz; i++) {
      int now = cur + i;
      C1 = (C1 + powchi * (msg1[i] + gmp_P - oprf_mac[now]) * alpha_mac[now] + powchi * (gmp_P - alpha[now]) * zk_mac[now] ) % gmp_P;
      C0 = (C0 + powchi * zk_mac[now] * alpha_mac[now]) % gmp_P;
      powchi = (powchi * chi) % gmp_P;
    }

    C1 = (C1 + gmp_P - pad1[0]) % gmp_P;
    C0 = (C0 + pad0[0]) % gmp_P;
    std::vector<uint8_t> hex_pi(96);
    hex_decompose(C1, &hex_pi[0]);
    hex_decompose(C0, &hex_pi[48]);
    io->send_data(&hex_pi[0], 96);
    io->flush();
    cur += sz;
  }  

  // batch eval
  void oprf_batch_eval_server(const int &sz) {
    if (is_malicious) {
      oprf_batch_eval_server_malicious(sz);
      return;
    }
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

  // batch eval --- libOTe
  void oprf_batch_eval_server(const int &sz, osuCrypto::Socket &sock) {
    if (is_malicious) {
      oprf_batch_eval_server_malicious(sz, sock);
      return;
    }
    std::vector<uint8_t> ext(48 * sz);
    std::vector<mpz_class> share(sz);
    vole.extend_sender(sock, &share[0], sz);
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

  // batch eval --- libOTe
  // base single
  void oprf_batch_eval_server_base(const int &sz, osuCrypto::Socket &sock) {
    if (is_malicious) {
      oprf_batch_eval_server_malicious_base(sz, sock);
      return;
    }
    std::vector<uint8_t> ext(48 * sz);
    std::vector<mpz_class> share(sz);
    //vole.extend_sender(sock, &share[0], sz);
    //basevole->triple_gen_send(share, sz);
    basevole2->triple_gen_send(share, sz);
    std::cout << "VOLE generations:" << std::endl;
    std::cout << "communication (B): " << com_test(ios)-com_main << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl;     
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


  void oprf_batch_eval_client_malicious(const mpz_class *x, const int &sz, std::vector<mpz_class> &y) {
    if (cur + sz > alpha.size()) malicious_offline(sz); // TODO: we can first use-up all the leftover correlations than extend
    std::vector<uint8_t> ext(48 * sz);
    y.resize(sz);
    std::vector<mpz_class> msg1(sz);
    for (int i = 0; i < sz; i++) {
      msg1[i] = (oprf_a[cur+i] * x[i] + oprf_mac[cur+i]) % gmp_P;
      hex_decompose(msg1[i], &ext[48 * i]);
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
    io->recv_data(&ext[0], 48 * sz);
    // send the random challenge after committing
    mpz_class chi = GMP_PRG_FP().sample();
    std::vector<uint8_t> hex_chi(48);
    hex_decompose(chi, &hex_chi[0]);
    io->send_data(&hex_chi[0], 48);
    io->flush();

    std::vector<mpz_class> msg2(sz);
    for (int i = 0; i < sz; i++) {
      msg2[i] = hex_compose(&ext[48 * i]);
      y[i] = gmp_raise(msg2[i] * gmp_inverse(oprf_a[i + cur]) % gmp_P);
    }
    // TODO: zkp for malicious behaviors

    mpz_class sq_zk_delta = zkDelta * zkDelta % gmp_P;
    mpz_class powchi = 1;
    mpz_class expect_pi = 0;
    for (int i = 0; i < sz; i++) {
      int now = cur + i;
      expect_pi = (expect_pi + powchi * ((zk_mac[now] + msg1[i] * zkDelta) * alpha_mac[now] + msg2[i] * sq_zk_delta)) % gmp_P;
      powchi = powchi * chi % gmp_P;
    }
    mpz_class pad;
    zkvole.extend_sender(&pad, 1);
    expect_pi = (expect_pi + pad) % gmp_P;
    //cout << expect_pi << endl;
    std::vector<uint8_t> hex_pi(96);
    io->recv_data(&hex_pi[0], 96);
    mpz_class C1 = hex_compose(&hex_pi[0]);
    mpz_class C0 = hex_compose(&hex_pi[48]);
    //cout << (C1 * zkDelta + C0) % gmp_P << endl;
    if ((C1 * zkDelta + C0) % gmp_P != expect_pi) {
      cout << "The server is cheating in the final opening!" << endl;
      abort();
    }
    cout << "opening check pass" << endl;
    cur += sz;
  }

  // with libOTe
  void oprf_batch_eval_client_malicious(const mpz_class *x, const int &sz, std::vector<mpz_class> &y, osuCrypto::Socket &sock) {
    if (cur + sz > alpha.size()) malicious_offline(sz, sock); // TODO: we can first use-up all the leftover correlations than extend
    std::vector<uint8_t> ext(48 * sz);
    y.resize(sz);
    std::vector<mpz_class> msg1(sz);
    for (int i = 0; i < sz; i++) {
      msg1[i] = (oprf_a[cur+i] * x[i] + oprf_mac[cur+i]) % gmp_P;
      hex_decompose(msg1[i], &ext[48 * i]);
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
    io->recv_data(&ext[0], 48 * sz);
    // send the random challenge after committing
    mpz_class chi = GMP_PRG_FP().sample();
    std::vector<uint8_t> hex_chi(48);
    hex_decompose(chi, &hex_chi[0]);
    io->send_data(&hex_chi[0], 48);
    io->flush();

    std::vector<mpz_class> msg2(sz);
    for (int i = 0; i < sz; i++) {
      msg2[i] = hex_compose(&ext[48 * i]);
      y[i] = gmp_raise(msg2[i] * gmp_inverse(oprf_a[i + cur]) % gmp_P);
    }
    // TODO: zkp for malicious behaviors

    mpz_class sq_zk_delta = zkDelta * zkDelta % gmp_P;
    mpz_class powchi = 1;
    mpz_class expect_pi = 0;
    for (int i = 0; i < sz; i++) {
      int now = cur + i;
      expect_pi = (expect_pi + powchi * ((zk_mac[now] + msg1[i] * zkDelta) * alpha_mac[now] + msg2[i] * sq_zk_delta)) % gmp_P;
      powchi = powchi * chi % gmp_P;
    }
    mpz_class pad;
    zkvole.extend_sender(sock, &pad, 1);
    expect_pi = (expect_pi + pad) % gmp_P;
    //cout << expect_pi << endl;
    std::vector<uint8_t> hex_pi(96);
    io->recv_data(&hex_pi[0], 96);
    mpz_class C1 = hex_compose(&hex_pi[0]);
    mpz_class C0 = hex_compose(&hex_pi[48]);
    //cout << (C1 * zkDelta + C0) % gmp_P << endl;
    if ((C1 * zkDelta + C0) % gmp_P != expect_pi) {
      cout << "The server is cheating in the final opening!" << endl;
      abort();
    }
    cout << "opening check pass" << endl;
    cur += sz;
  }  

  // with libOTe
  // base single
  void oprf_batch_eval_client_malicious_base(const mpz_class *x, const int &sz, std::vector<mpz_class> &y, osuCrypto::Socket &sock) {
    std::vector<mpz_class> pad(1);    
    //basezkvole->triple_gen_send(pad, 1);    
    basezkvole2->triple_gen_send(pad, 1);    
    if (cur + sz > alpha.size()) malicious_offline_base(sz, sock); // TODO: we can first use-up all the leftover correlations than extend
    std::vector<uint8_t> ext(48 * sz);
    y.resize(sz);
    std::vector<mpz_class> msg1(sz);
    for (int i = 0; i < sz; i++) {
      msg1[i] = (oprf_a[cur+i] * x[i] + oprf_mac[cur+i]) % gmp_P;
      hex_decompose(msg1[i], &ext[48 * i]);
    }
    io->send_data(&ext[0], 48 * sz);
    io->flush();
    io->recv_data(&ext[0], 48 * sz);
    // send the random challenge after committing
    mpz_class chi = GMP_PRG_FP().sample();
    std::vector<uint8_t> hex_chi(48);
    hex_decompose(chi, &hex_chi[0]);
    io->send_data(&hex_chi[0], 48);
    io->flush();

    std::vector<mpz_class> msg2(sz);
    for (int i = 0; i < sz; i++) {
      msg2[i] = hex_compose(&ext[48 * i]);
      y[i] = gmp_raise(msg2[i] * gmp_inverse(oprf_a[i + cur]) % gmp_P);
    }
    // TODO: zkp for malicious behaviors

    mpz_class sq_zk_delta = zkDelta * zkDelta % gmp_P;
    mpz_class powchi = 1;
    mpz_class expect_pi = 0;
    for (int i = 0; i < sz; i++) {
      int now = cur + i;
      expect_pi = (expect_pi + powchi * ((zk_mac[now] + msg1[i] * zkDelta) * alpha_mac[now] + msg2[i] * sq_zk_delta)) % gmp_P;
      powchi = powchi * chi % gmp_P;
    }
    expect_pi = (expect_pi + pad[0]) % gmp_P;
    //cout << expect_pi << endl;
    std::vector<uint8_t> hex_pi(96);
    io->recv_data(&hex_pi[0], 96);
    mpz_class C1 = hex_compose(&hex_pi[0]);
    mpz_class C0 = hex_compose(&hex_pi[48]);
    //cout << (C1 * zkDelta + C0) % gmp_P << endl;
    if ((C1 * zkDelta + C0) % gmp_P != expect_pi) {
      cout << "The server is cheating in the final opening!" << endl;
      abort();
    }
    cout << "opening check pass" << endl;
    cur += sz;
  }  

  void oprf_batch_eval_client(const mpz_class *x, const int &sz, std::vector<mpz_class> &y) {
    if (is_malicious) {
      oprf_batch_eval_client_malicious(x, sz, y);
      return;
    }
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

  // batch eval --- libOTe
  void oprf_batch_eval_client(const mpz_class *x, const int &sz, std::vector<mpz_class> &y, osuCrypto::Socket &sock) {
    if (is_malicious) {
      oprf_batch_eval_client_malicious(x, sz, y, sock);
      return;
    }
    std::vector<uint8_t> ext(48 * sz);
    y.resize(sz);
    std::vector<mpz_class> share(sz), a(sz);
    vole.extend_recver(sock, &share[0], &a[0], sz);
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

  // batch eval --- libOTe
  // base single
  void oprf_batch_eval_client_base(const mpz_class *x, const int &sz, std::vector<mpz_class> &y, osuCrypto::Socket &sock) {
    if (is_malicious) {
      oprf_batch_eval_client_malicious_base(x, sz, y, sock); // TODO: update this
      return;
    }
    std::vector<uint8_t> ext(48 * sz);
    y.resize(sz);
    std::vector<mpz_class> share(sz), a(sz);
    //vole.extend_recver(sock, &share[0], &a[0], sz);
    //basevole->triple_gen_recv(share, a, sz);
    basevole2->triple_gen_recv(share, a, sz);
    std::cout << "VOLE generations:" << std::endl;
    std::cout << "communication (B): " << com_test(ios)-com_main << std::endl;
    std::cout << "comm. libOT (B): " << sock.bytesReceived()+sock.bytesSent() << std::endl; 
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