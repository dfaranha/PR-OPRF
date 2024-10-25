#ifndef OPRF_BASE_VOLE_H__
#define OPRF_BASE_VOLE_H__

#include "emp-tool/emp-tool.h"
#include "oprf/util/oprf-cope.h"

template <typename IO> class SVOLE_GGM {
public:
  int party;
  IO *io;
  int depth;

  SVOLE_GGM(int party, IO *io, int depth) {
    this->party = party;
    this->io = io;
    this->depth = depth;
  }

  void ggm_send(osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &sMsgs, const int idx, std::vector<block> &seed) {
    block seed_tree[depth][1<<depth];
    PRG prg;
    prg.random_block(&seed_tree[0][0], 2);
    for (int i = 0; i < depth-1; i++) {
      int shift = 1<<(i+1);
      block left_sum, right_sum;
      memcpy(&left_sum, &sMsgs[idx+i][1], sizeof(block));
      memcpy(&right_sum, &sMsgs[idx+i][0], sizeof(block));
      for (int j = 0; j < shift; j++) {
        PRG prg1(&seed_tree[i][j]);
        prg1.random_block(&seed_tree[i+1][j<<1], 2);
        if (j&1) right_sum ^= seed_tree[i][j];
        else left_sum ^= seed_tree[i][j];
      }
      io->send_data(&left_sum, sizeof(block));
      io->send_data(&right_sum, sizeof(block));
    }
    int shift = 1<<depth;
    block left_sum, right_sum;
    memcpy(&left_sum, &sMsgs[idx+depth-1][1], sizeof(block));
    memcpy(&right_sum, &sMsgs[idx+depth-1][0], sizeof(block));    
    seed.resize(1<<depth);
    for (int j = 0; j < shift; j++) {
      seed[j] = seed_tree[depth-1][j];
      if (j&1) right_sum ^= seed_tree[depth-1][j];
      else left_sum ^= seed_tree[depth-1][j];      
    }
    io->send_data(&left_sum, sizeof(block));
    io->send_data(&right_sum, sizeof(block));
    io->flush();
  }

  void ggm_recv(osuCrypto::AlignedUnVector<osuCrypto::block> &rMsgs, osuCrypto::BitVector &choices, const int idx, std::vector<block> &seed, int &punch) {
    block seed_tree[depth][1<<depth];
    punch = 0;
    for (int i = 0; i < depth-1; i++) {
      if (choices[idx+i] == 1) punch = (punch<<1)+1;
      else punch <<= 1;
      int shift = 1<<(i+1);
      int pos = punch^1;
      memcpy(&seed_tree[i][pos], &rMsgs[idx+i], sizeof(block));
      block left_sum, right_sum;
      io->recv_data(&left_sum, sizeof(block));
      io->recv_data(&right_sum, sizeof(block));
      if (choices[idx+i] == 0) {
        seed_tree[i][pos] ^= right_sum;
      } else {
        seed_tree[i][pos] ^= left_sum;
      }
      for (int j = pos & 1; j < shift; j += 2) {
        if (j == pos) continue;
        seed_tree[i][pos] ^= seed_tree[i][j];
      }
      for (int j = 0; j < shift; j++) {
        if (j == punch) continue;
        PRG prg(&seed_tree[i][j]);
        prg.random_block(&seed_tree[i+1][j<<1], 2);
      }
    }
    {
      if (choices[idx+depth-1] == 1) punch = (punch<<1)+1;
      else punch <<= 1;
      int shift = 1<<depth;
      int pos = punch^1;
      memcpy(&seed_tree[depth-1][pos], &rMsgs[idx+depth-1], sizeof(block));
      block left_sum, right_sum;
      io->recv_data(&left_sum, sizeof(block));
      io->recv_data(&right_sum, sizeof(block));
      if (choices[idx+depth-1] == 0) {
        seed_tree[depth-1][pos] ^= right_sum;
      } else {
        seed_tree[depth-1][pos] ^= left_sum;
      }
      for (int j = pos & 1; j < shift; j += 2) {
        if (j == pos) continue;
        seed_tree[depth-1][pos] ^= seed_tree[depth-1][j];
      }
      seed.resize(1<<depth);
      for (int j = 0; j < shift; j++) {
        seed[j] = seed_tree[depth-1][j];
      }    
    }
  }
};

template <typename IO> class OprfBaseVole {
public:
  int party;
  int m;
  IO *io;
  OprfCope<IO> cope;
  mpz_class Delta;

  // SENDER
  OprfBaseVole(int party, IO *io, mpz_class Delta) : cope(party, io, oprf_P_len) {
    this->party = party;
    this->io = io;
    this->Delta = Delta;
    cope.initialize(Delta);
  }

  // SENDER_LIBOT
  OprfBaseVole(int party, IO *io, mpz_class &Delta, osuCrypto::Socket &sock) : cope(party, io, oprf_P_len) {
    this->party = party;
    this->io = io;
    cope.initialize(Delta, sock);    
    this->Delta = Delta;
  }  

  // SENDER_LIBOT
  // For Malicious Single Point
  // Save More by OT Extensions to Operate As Seeds in Other Direction
  OprfBaseVole(int party, IO *io, mpz_class &Delta, osuCrypto::Socket &sock, bool exists) : cope(party, io, oprf_P_len) {
    this->party = party;
    this->io = io;
    cope.initialize(Delta, sock, exists);    
    this->Delta = Delta;
  }    

  // RECEIVER
  OprfBaseVole(int party, IO *io) : cope(party, io, oprf_P_len) {
    this->party = party;
    this->io = io;
    cope.initialize();
  }

  // RECEIVER_LIBOT
  OprfBaseVole(int party, IO *io, osuCrypto::Socket &sock) : cope(party, io, oprf_P_len) {
    this->party = party;
    this->io = io;
    cope.initialize(sock);
  }

  // RECEIVER_LIBOT
  // For Malicious Single Point
  // Save More by OT Extensions to Operate As Seeds in Other Direction
  OprfBaseVole(int party, IO *io, osuCrypto::Socket &sock, bool exists) : cope(party, io, oprf_P_len) {
    this->party = party;
    this->io = io;
    cope.initialize(sock, exists);
  }

  // sender
  void triple_gen_send(std::vector<mpz_class> &share, const int size) {
    cope.extend(share, size);
    mpz_class b = cope.extend();
    sender_check(share, b, size);
  }

  // recver
  void triple_gen_recv(std::vector<mpz_class> &share, std::vector<mpz_class> &x, const int size) {
    x.resize(size);
    GMP_PRG_FP prg;
    for (int i = 0; i < size; i++) x[i] = prg.sample();
    cope.extend(share, x, size);
    mpz_class c = prg.sample();
    mpz_class b = cope.extend(c);
    recver_check(share, x, c, b, size);
  }

  // sender check
  void sender_check(std::vector<mpz_class> &share, mpz_class b, const int size) {
    GMP_PRG_FP prg;
    mpz_class chi = prg.sample();
    std::vector<uint8_t> chi_de(oprf_P_len / 8);
    hex_decompose(chi, &chi_de[0]);
    io->send_data(&chi_de[0], oprf_P_len / 8);
    io->flush();

    // universal polynomial hash
    mpz_class acc_coeff = chi;
    mpz_class acc_pi = b;

    // inner product
    for (int i = 0; i < size; i++) {
      acc_pi = (acc_pi + acc_coeff * share[i]);
      acc_coeff = (acc_coeff * chi) % gmp_P;
    }
    acc_pi %= gmp_P;

    io->recv_data(&chi_de[0], oprf_P_len / 8);
    mpz_class xz0 = hex_compose(&chi_de[0]);
    io->recv_data(&chi_de[0], oprf_P_len / 8);
    mpz_class xz1 = hex_compose(&chi_de[0]);

    xz1 = (xz1 * Delta) % gmp_P;
    acc_pi = (acc_pi + xz1) % gmp_P;
    if (acc_pi != xz0) {
      std::cout << "base VOLE check fails" << std::endl;
      abort();      
    }
  }

  // receiver check
  void recver_check(std::vector<mpz_class> &share, std::vector<mpz_class> &x, mpz_class c, mpz_class b, const int size) {
    std::vector<uint8_t> chi_de(oprf_P_len / 8);
    io->recv_data(&chi_de[0], oprf_P_len / 8);
    mpz_class chi = hex_compose(&chi_de[0]);

    // uni poly hash
    mpz_class acc_coeff = chi;
    mpz_class acc_pi0 = b;
    mpz_class acc_pi1 = c;

    // inner product
    for (int i = 0; i < size; i++) {
      acc_pi0 = (acc_pi0 + acc_coeff * share[i]); // % gmp_P;
      acc_pi1 = (acc_pi1 + acc_coeff * x[i]); // % gmp_P;
      acc_coeff = (acc_coeff * chi) % gmp_P;
    }
    acc_pi0 %= gmp_P;
    acc_pi1 %= gmp_P;

    for (int i = 0; i < 48; i++) chi_de[i] = 0;
    hex_decompose(acc_pi0, &chi_de[0]);
    io->send_data(&chi_de[0], oprf_P_len / 8);
    for (int i = 0; i < 48; i++) chi_de[i] = 0;
    hex_decompose(acc_pi1, &chi_de[0]);
    io->send_data(&chi_de[0], oprf_P_len / 8);
    io->flush();
  }

};


template <typename IO> class SoftSpokenOprfBaseVole {
public:
  int party;
  IO *io;
  mpz_class Delta;
  int cur;

  std::vector<mpz_class> W;
  std::vector<mpz_class> U;
  std::vector<mpz_class> V;  

  SoftSpokenOprfBaseVole(int party, IO *io) {
    this->party = party;
    this->io = io;
  }

  void sender_prepare(int m, osuCrypto::Socket &sock) {
    cur = 0;

    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> sMsgs(softspoken_t * softspoken_rep);

    OTExtTypeSender sender;
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    // setup base OTs
    sender.setBaseOts(saved_rMsgs, saved_choices);

    // OT extension
    coproto::sync_wait(sender.send(sMsgs, prng, sock));
    coproto::sync_wait(sock.flush());

    SVOLE_GGM ggm(party, io, softspoken_t);

    int shift = 1 << softspoken_t;

    std::vector<GMP_PRG_FP> G(softspoken_rep * shift);
    std::vector<block> seed;
    for (int i = 0; i < softspoken_rep; i++) {      
      ggm.ggm_send(sMsgs, i*softspoken_t, seed);
      for (int j = 0; j < shift; j++)
        G[i * shift + j].reseed(&seed[j]);
    }

    std::vector<mpz_class> u(softspoken_rep * (m+1));
    std::vector<mpz_class> w(softspoken_rep * (m+1));
    for (int i = 0; i < softspoken_rep; i++) {
      for (int j = 0; j < m+1; j++) {
        mpz_class tmpu, tmpw;
        for (int k = 0; k < shift; k++) {
          mpz_class tmp(k+1);          
          mpz_class sa = G[i * shift + k].sample();
          tmpu = tmpu + sa;
          tmpw = tmpw + tmp * sa;
        }
        u[i * (m+1) + j] = tmpu % gmp_P;
        w[i * (m+1) + j] = tmpw % gmp_P;
      }
    }
    
    for (int i = 1; i < softspoken_rep; i++) {
      for (int j = 0; j < m+1; j++) {
        mpz_class diff = (u[i * (m+1) + j] + gmp_P - u[j]) % gmp_P;
        std::vector<uint8_t> ext(48);
        hex_decompose(diff, &ext[0]);
        io->send_data(&ext[0], 48);
      }
      io->flush();
    }

    block prg_seed;
    io->recv_data(&prg_seed, sizeof(block));
    GMP_PRG_FP pprg(&prg_seed);

    std::vector<mpz_class> coeff(softspoken_rep);
    for (int i = 0; i < softspoken_rep; i++) coeff[i] = pprg.sample();
    U.resize(m); W.resize(m);

    for (int i = 0; i < m; i++) {
      mpz_class acc_w;
      for (int j = 0; j < softspoken_rep; j++) {
        acc_w = (acc_w + w[j * (m+1) + i] * coeff[j]) % gmp_P;
      }      
      U[i] = u[i];
      W[i] = acc_w;
    }
    
  }

  void receiver_prepare(int m, osuCrypto::Socket &sock) {
    cur = 0;

    osuCrypto::BitVector choices(softspoken_t * softspoken_rep);
    osuCrypto::AlignedUnVector<osuCrypto::block> rMsgs(softspoken_t * softspoken_rep);
    OTExtTypeReceiver receiver;
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    receiver.setBaseOts(saved_sMsgs);

    // OT extension
    choices.randomize(prng);
    coproto::sync_wait(receiver.receive(choices, rMsgs, prng, sock));
    coproto::sync_wait(sock.flush());       

    SVOLE_GGM ggm(party, io, softspoken_t); 
    std::vector<int> punch(softspoken_rep);  

    int shift = 1 << softspoken_t;  

    std::vector<GMP_PRG_FP> G(softspoken_rep * shift);
    std::vector<block> seed;
    for (int i = 0; i < softspoken_rep; i++) {
      ggm.ggm_recv(rMsgs, choices, i*softspoken_t, seed, punch[i]);
      for (int j = 0; j < shift; j++)
        G[i * shift + j].reseed(&seed[j]);
    }    

    std::vector<mpz_class> v(softspoken_rep * (m+1));
    for (int i = 0; i < softspoken_rep; i++) {
      for (int j = 0; j < m+1; j++) {
        mpz_class tmpv;
        for (int k = 0; k < shift; k++) {
          if (k == punch[i]) continue;
          mpz_class tmp(k-punch[i]);
          tmp = (tmp + gmp_P) % gmp_P;
          tmpv = tmpv + tmp * G[i * shift + k].sample();
        }
        v[i * (m+1) + j] = tmpv % gmp_P;
      }
    }

    std::vector<uint8_t> ext(48);
    for (int i = 1; i < softspoken_rep; i++) {
      for (int j = 0; j < m+1; j++) {
        io->recv_data(&ext[0], 48);
        v[i * (m+1) + j] += hex_compose(&ext[0]) * (punch[i]+1);
        v[i * (m+1) + j] %= gmp_P;
      }
    }    

    PRG prg;
    block prg_seed;
    prg.random_block(&prg_seed);
    io->send_data(&prg_seed, sizeof(block));
    io->flush();

    GMP_PRG_FP pprg(&prg_seed);

    std::vector<mpz_class> coeff(softspoken_rep);
    for (int i = 0; i < softspoken_rep; i++) coeff[i] = pprg.sample();
    V.resize(m);

    for (int i = 0; i < m; i++) {
      mpz_class acc_v;
      for (int j = 0; j < softspoken_rep; j++) {
        acc_v = (acc_v + v[j * (m+1) + i] * coeff[j]) % gmp_P;
      }      
      V[i] = acc_v;
    }
    for (int i = 0; i < softspoken_rep; i++) 
      Delta = (Delta + coeff[i] * (punch[i]+1)) % gmp_P;

  }

  // sender
  void triple_gen_send(std::vector<mpz_class> &share, const int size) {
    if (cur + size > V.size()) {
      exit(-1);
    }
    share.resize(size);
    for (int i = 0; i < size; i++) share[i] = V[cur+i];
    cur += size;
  }

  // recv
  void triple_gen_recv(std::vector<mpz_class> &share, std::vector<mpz_class> &x, const int size) {
    if (cur + size > U.size()) {
      exit(-1);
    }
    share.resize(size);
    x.resize(size);
    for (int i = 0; i < size; i++) {
      share[i] = W[cur+i];
      x[i] = U[cur+i];
    }
    cur += size;
  }
  
};

#endif
