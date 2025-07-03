#ifndef OPRF_VOLE_TRIPLE_H_
#define OPRF_VOLE_TRIPLE_H_
#include "oprf/util/oprf-basevole.h"
#include "oprf/util/oprf-lpn.h"
#include "oprf/util/oprf-mpfss.h"

class OprfPrimalLPNParameterFp {
public:
  int64_t n, t, k, log_bin_sz;
  int64_t n_pre, t_pre, k_pre, log_bin_sz_pre;
  int64_t n_pre0, t_pre0, k_pre0, log_bin_sz_pre0;

  OprfPrimalLPNParameterFp() {}
  OprfPrimalLPNParameterFp(int64_t n, int64_t t, int64_t k, int64_t log_bin_sz,
                         int64_t n_pre, int64_t t_pre, int64_t k_pre,
                         int64_t log_bin_sz_pre, int64_t n_pre0, int64_t t_pre0,
                         int64_t k_pre0, int64_t log_bin_sz_pre0)
      : n(n), t(t), k(k), log_bin_sz(log_bin_sz), n_pre(n_pre), t_pre(t_pre),
        k_pre(k_pre), log_bin_sz_pre(log_bin_sz_pre), n_pre0(n_pre0),
        t_pre0(t_pre0), k_pre0(k_pre0), log_bin_sz_pre0(log_bin_sz_pre0) {

    if (n != t * (1 << log_bin_sz) || n_pre != t_pre * (1 << log_bin_sz_pre) ||
        n_pre < k + t + 1)
      error("LPN parameter not matched");
  }
  int64_t buf_sz() const { return n - t - k - 1; }
};

#ifndef ENABLE_SMALLN
const static OprfPrimalLPNParameterFp oprf_fp_default = OprfPrimalLPNParameterFp(
  10168320, 4965, 158000, 11, 166400, 2600, 5060, 6, 9600, 600, 1220, 4); 
#else
const static OprfPrimalLPNParameterFp oprf_fp_default = OprfPrimalLPNParameterFp(
  166400, 2600, 5060, 6, 166400, 2600, 5060, 6, 9600, 600, 1220, 4); 
#endif

// 9600 / 600 = 16 = 2^4
// 166400 / 2600 = 2^6
// 10168320 / 4965 = 2^11
// 317760 / 4965 = 2^6
// 10168320, 4965, 158000, 11,

template <typename IO> class OprfVoleTriple {
public:
  IO *io;
  IO **ios;
  int party;
  int threads;
  OprfPrimalLPNParameterFp param;
  int noise_type;
  int M;
  int ot_used, ot_limit;
  bool is_malicious;
  bool extend_initialized;
  bool pre_ot_inplace;
  std::vector<mpz_class> pre_yz, pre_x, vole_triples, vole_x;

  BaseCot<IO> *cot = nullptr;
  OTPre<IO> *pre_ot = nullptr;
  LibOTPre<IO> *lib_pre_ot = nullptr;

  mpz_class Delta;
  OprfLpnFp<10> *lpn = nullptr;
  ThreadPool *pool = nullptr;
  OprfMpfssRegFp<IO> *mpfss = nullptr;

  OprfVoleTriple(int party, int threads, IO **ios,
             OprfPrimalLPNParameterFp param = oprf_fp_default) {
    this->io = ios[0];
    this->threads = threads;
    this->party = party;
    this->ios = ios;
    this->param = param;
    this->extend_initialized = false;

    cot = new BaseCot<IO>(party, io, true);
    cot->cot_gen_pre();

    pool = new ThreadPool(threads);
  }

  OprfVoleTriple(int party, int threads, IO **ios, osuCrypto::Socket &sock,
             OprfPrimalLPNParameterFp param = oprf_fp_default) {
    this->io = ios[0];
    this->threads = threads;
    this->party = party;
    this->ios = ios;
    this->param = param;
    this->extend_initialized = false;

    // cot = new BaseCot<IO>(party, io, true);
    // cot->cot_gen_pre();


    pool = new ThreadPool(threads);
  }  

  ~OprfVoleTriple() {
    if (pre_ot != nullptr)
      delete pre_ot;
    if (lib_pre_ot != nullptr)
      delete lib_pre_ot;
    if (lpn != nullptr)
      delete lpn;
    if (pool != nullptr)
      delete pool;
    if (mpfss != nullptr)
      delete mpfss;
    if (cot != nullptr)
      delete cot;
  }

  void setup(mpz_class delta) {
    this->Delta = delta;
    setup();
  }

  // with libOTe
  void setup(mpz_class& delta, osuCrypto::Socket &sock) {
    libsetup(delta, sock);
  }  

  mpz_class delta() {
    if (party == ALICE)
      return this->Delta;
    else {
      error("No delta for BOB");
      return 0;
    }
  }

  void extend_initialization() {
    lpn = new OprfLpnFp<10>(param.n, param.k, pool, pool->size());
    mpfss = new OprfMpfssRegFp<IO>(party, threads, param.n, param.t,
                               param.log_bin_sz, pool, ios);
    mpfss->set_malicious();

    pre_ot = new OTPre<IO>(io, mpfss->tree_height - 1, mpfss->tree_n);
    M = param.k + param.t + 1;
    ot_limit = param.n - M;
    ot_used = ot_limit;
    extend_initialized = true;
  }

  // for libOTe
  void extend_initialization(osuCrypto::Socket &sock) {
    lpn = new OprfLpnFp<10>(param.n, param.k, pool, pool->size());
    mpfss = new OprfMpfssRegFp<IO>(party, threads, param.n, param.t,
                               param.log_bin_sz, pool, ios);
    mpfss->set_malicious();

    lib_pre_ot = new LibOTPre<IO>(io, mpfss->tree_height - 1, mpfss->tree_n);
    if (party == ALICE) lib_pre_ot->send_gen_pre(sock);
    else lib_pre_ot->recv_gen_pre(sock);      

    M = param.k + param.t + 1;
    ot_limit = param.n - M;
    ot_used = ot_limit;
    extend_initialized = true;
  }

  // sender extend
  void extend_send(mpz_class *y, OprfMpfssRegFp<IO> *mpfss, OTPre<IO> *pre_ot,
                   OprfLpnFp<10> *lpn, mpz_class *key) {
    mpfss->sender_init(Delta);
    __uint128_t *sparse_vec = new __uint128_t[lpn->n];
    mpfss->mpfss(pre_ot, key, sparse_vec, y);
    lpn->compute_send(y, key + mpfss->tree_n + 1);
    delete[] sparse_vec;
  }

  // sender extend --- libOTe
  void extend_send(mpz_class *y, OprfMpfssRegFp<IO> *mpfss, LibOTPre<IO> *pre_ot,
                   OprfLpnFp<10> *lpn, mpz_class *key) {
    mpfss->sender_init(Delta);
    __uint128_t *sparse_vec = new __uint128_t[lpn->n];
    mpfss->mpfss(pre_ot, key, sparse_vec, y);
    lpn->compute_send(y, key + mpfss->tree_n + 1);
    delete[] sparse_vec;
  }  

  // receiver extend
  void extend_recv(mpz_class *z, mpz_class *val, OprfMpfssRegFp<IO> *mpfss, OTPre<IO> *pre_ot,
                   OprfLpnFp<10> *lpn, mpz_class *mac, mpz_class *X) {
    mpfss->recver_init();
    __uint128_t *sparse_vec = new __uint128_t[lpn->n];
    mpfss->mpfss(pre_ot, mac, sparse_vec, z, X); // pause here
    for (int i = 0; i < lpn->n; i++) val[i] = 0;
    for (int i = 0; i < mpfss->tree_n; i++) {
      val[ mpfss->leave_n*i+mpfss->item_pos_recver[i] ] = X[i];
    }
    lpn->compute_recv(z, val, mac + mpfss->tree_n + 1, X + mpfss->tree_n + 1);
    delete[] sparse_vec;
  }

  // receiver extend
  void extend_recv(mpz_class *z, mpz_class *val, OprfMpfssRegFp<IO> *mpfss, LibOTPre<IO> *pre_ot,
                   OprfLpnFp<10> *lpn, mpz_class *mac, mpz_class *X) {
    mpfss->recver_init();
    __uint128_t *sparse_vec = new __uint128_t[lpn->n];
    mpfss->mpfss(pre_ot, mac, sparse_vec, z, X); // pause here
    for (int i = 0; i < lpn->n; i++) val[i] = 0;
    for (int i = 0; i < mpfss->tree_n; i++) {
      val[ mpfss->leave_n*i+mpfss->item_pos_recver[i] ] = X[i];
    }
    lpn->compute_recv(z, val, mac + mpfss->tree_n + 1, X + mpfss->tree_n + 1);
    delete[] sparse_vec;
  }


  void extend(mpz_class *buffer, mpz_class *buffer_x = NULL) {
    cot->cot_gen(pre_ot, pre_ot->n);
    // memset(buffer, 0, n*sizeof(__uint128_t));
    if (party == ALICE) {
      extend_send(buffer, mpfss, pre_ot, lpn, &pre_yz[0]);
      for (int i = 0; i < M; i++) pre_yz[i] = buffer[ot_limit+i];
    } else {
      extend_recv(buffer, buffer_x, mpfss, pre_ot, lpn, &pre_yz[0], &pre_x[0]);
      for (int i = 0; i < M; i++) {
        pre_yz[i] = buffer[ot_limit+i];
        pre_x[i] = buffer_x[ot_limit+i];
      }
    }
    //memcpy(pre_yz, buffer + ot_limit, M * sizeof(__uint128_t));
  }

  void extend(osuCrypto::Socket &sock, mpz_class *buffer, mpz_class *buffer_x = NULL) {
    //cot->cot_gen(pre_ot, pre_ot->n);
    // memset(buffer, 0, n*sizeof(__uint128_t));
    if (party == ALICE) {
      lib_pre_ot->send_gen(sock);
      extend_send(buffer, mpfss, lib_pre_ot, lpn, &pre_yz[0]);
      for (int i = 0; i < M; i++) pre_yz[i] = buffer[ot_limit+i];
    } else {
      lib_pre_ot->recv_gen(sock);
      extend_recv(buffer, buffer_x, mpfss, lib_pre_ot, lpn, &pre_yz[0], &pre_x[0]);
      for (int i = 0; i < M; i++) {
        pre_yz[i] = buffer[ot_limit+i];
        pre_x[i] = buffer_x[ot_limit+i];
      }
    }
    //memcpy(pre_yz, buffer + ot_limit, M * sizeof(__uint128_t));
  }

  void setup() {
    // initialize the main process
    ThreadPool pool_tmp(1);
    auto fut = pool_tmp.enqueue([this]() { extend_initialization(); });

    // space for pre-processing triples
    std::vector<mpz_class> pre_yz0(param.n_pre0);
    std::vector<mpz_class> pre_x0;
    if (party == BOB) pre_x0.resize(param.n_pre0);

    // pre-processing tools
    OprfLpnFp<10> lpn_pre0(param.n_pre0, param.k_pre0, pool, pool->size());
    OprfMpfssRegFp<IO> mpfss_pre0(party, threads, param.n_pre0, param.t_pre0,
                              param.log_bin_sz_pre0, pool, ios);
    mpfss_pre0.set_malicious();
    OTPre<IO> pre_ot_ini0(ios[0], mpfss_pre0.tree_height - 1,
                          mpfss_pre0.tree_n);

    // generate tree_n*(depth-1) COTs
    cot->cot_gen(&pre_ot_ini0, pre_ot_ini0.n);

    // generate 2*tree_n+k_pre triples and extend
    OprfBaseVole<IO> *svole0;
    int triple_n0 = 1 + mpfss_pre0.tree_n + param.k_pre0;
    if (party == ALICE) {
      std::vector<mpz_class> key(triple_n0);
      svole0 = new OprfBaseVole<IO>(party, ios[0], Delta);
      svole0->triple_gen_send(key, triple_n0);

      extend_send(&pre_yz0[0], &mpfss_pre0, &pre_ot_ini0, &lpn_pre0, &key[0]);
    } else {
      std::vector<mpz_class> mac(triple_n0);
      std::vector<mpz_class> X(triple_n0);
      svole0 = new OprfBaseVole<IO>(party, ios[0]);
      svole0->triple_gen_recv(mac, X, triple_n0);

      // one more argument to save expanding X
      extend_recv(&pre_yz0[0], &pre_x0[0], &mpfss_pre0, &pre_ot_ini0, &lpn_pre0, &mac[0], &X[0]);
    }
    delete svole0;

    // space for pre-processing triples
    pre_yz.resize(param.n_pre);
    pre_x.resize(param.n_pre);

    // pre-processing tools
    OprfLpnFp<10> lpn_pre(param.n_pre, param.k_pre, pool, pool->size());
    OprfMpfssRegFp<IO> mpfss_pre(party, threads, param.n_pre, param.t_pre,
                             param.log_bin_sz_pre, pool, ios);
    mpfss_pre.set_malicious();
    OTPre<IO> pre_ot_ini(ios[0], mpfss_pre.tree_height - 1, mpfss_pre.tree_n);

    // generate tree_n*(depth-1) COTs
    cot->cot_gen(&pre_ot_ini, pre_ot_ini.n);

    // generate 2*tree_n+k_pre triples and extend
    if (party == ALICE) {
      extend_send(&pre_yz[0], &mpfss_pre, &pre_ot_ini, &lpn_pre, &pre_yz0[0]);
    } else {
      extend_recv(&pre_yz[0], &pre_x[0], &mpfss_pre, &pre_ot_ini, &lpn_pre, &pre_yz0[0], &pre_x0[0]);
    }
    pre_ot_inplace = true;

    fut.get();
  }

  // libot's version setup
  void libsetup(mpz_class& delta, osuCrypto::Socket &sock) {
    // initialize the main process
    //ThreadPool pool_tmp(1);
    //auto fut = pool_tmp.enqueue([this]() { libot_extend_initialization(); });

#ifndef ENABLE_SMALLN    
    // space for pre-processing triples
    std::vector<mpz_class> pre_yz0(param.n_pre0);
    std::vector<mpz_class> pre_x0;
    if (party == BOB) pre_x0.resize(param.n_pre0);
#else
    // this is for smaller test case
    pre_yz.resize(param.n_pre);
    pre_x.resize(param.n_pre);
#endif

    // pre-processing tools
    OprfLpnFp<10> lpn_pre0(param.n_pre0, param.k_pre0, pool, pool->size());
    OprfMpfssRegFp<IO> mpfss_pre0(party, threads, param.n_pre0, param.t_pre0,
                              param.log_bin_sz_pre0, pool, ios);
    mpfss_pre0.set_malicious();
    LibOTPre<IO> pre_ot_ini0(ios[0], mpfss_pre0.tree_height - 1,
                          mpfss_pre0.tree_n);

    // generate tree_n*(depth-1) COTs
    //cot->cot_gen(&pre_ot_ini0, pre_ot_ini0.n);
    if (party == ALICE) {
      pre_ot_ini0.send_gen_pre(sock);
      pre_ot_ini0.send_gen(sock);
    } else {
      pre_ot_ini0.recv_gen_pre(sock);
      pre_ot_ini0.recv_gen(sock);
    }

    // generate 2*tree_n+k_pre triples and extend
    SoftSpokenOprfBaseVole<IO> *svole0;
    int triple_n0 = 1 + mpfss_pre0.tree_n + param.k_pre0;
    if (party == ALICE) {
      std::vector<mpz_class> key(triple_n0);

      svole0 = new SoftSpokenOprfBaseVole<IO>(party, ios[0]); //, delta, sock);
      svole0->receiver_prepare(triple_n0, sock);

      this->Delta = delta = svole0->Delta;
      svole0->triple_gen_send(key, triple_n0); 

#ifndef ENABLE_SMALLN      
      extend_send(&pre_yz0[0], &mpfss_pre0, &pre_ot_ini0, &lpn_pre0, &key[0]);
#else
      extend_send(&pre_yz[0], &mpfss_pre0, &pre_ot_ini0, &lpn_pre0, &key[0]);
#endif
    } else {
      std::vector<mpz_class> mac(triple_n0);
      std::vector<mpz_class> X(triple_n0);

      svole0 = new SoftSpokenOprfBaseVole<IO>(party, ios[0]); //, sock);
      svole0->sender_prepare(triple_n0, sock);

      svole0->triple_gen_recv(mac, X, triple_n0);

      // one more argument to save expanding X
#ifndef ENABLE_SMALLN
      extend_recv(&pre_yz0[0], &pre_x0[0], &mpfss_pre0, &pre_ot_ini0, &lpn_pre0, &mac[0], &X[0]);
#else
      extend_recv(&pre_yz[0], &pre_x[0], &mpfss_pre0, &pre_ot_ini0, &lpn_pre0, &mac[0], &X[0]);
#endif
    }
    delete svole0;


#ifndef ENABLE_SMALLN
    // space for pre-processing triples
    pre_yz.resize(param.n_pre);
    pre_x.resize(param.n_pre);

    // pre-processing tools
    OprfLpnFp<10> lpn_pre(param.n_pre, param.k_pre, pool, pool->size());
    OprfMpfssRegFp<IO> mpfss_pre(party, threads, param.n_pre, param.t_pre,
                             param.log_bin_sz_pre, pool, ios);
    mpfss_pre.set_malicious();
    LibOTPre<IO> pre_ot_ini(ios[0], mpfss_pre.tree_height - 1, mpfss_pre.tree_n);

    // generate tree_n*(depth-1) COTs
    //cot->cot_gen(&pre_ot_ini, pre_ot_ini.n);

    if (party == ALICE) {
      pre_ot_ini.send_gen_pre(sock);
      pre_ot_ini.send_gen(sock);      
    } else {
      pre_ot_ini.recv_gen_pre(sock);
      pre_ot_ini.recv_gen(sock);
    }

    // generate 2*tree_n+k_pre triples and extend
    if (party == ALICE) {
      extend_send(&pre_yz[0], &mpfss_pre, &pre_ot_ini, &lpn_pre, &pre_yz0[0]);
    } else {
      extend_recv(&pre_yz[0], &pre_x[0], &mpfss_pre, &pre_ot_ini, &lpn_pre, &pre_yz0[0], &pre_x0[0]);
    }
    pre_ot_inplace = true;

    //fut.get();
#endif

    extend_initialization(sock);  

  }  

  void extend_sender(mpz_class *data_yz, int num) {
    if (vole_triples.size() == 0) vole_triples.resize(param.n);
    if (extend_initialized == false)
      error("Run setup before extending");
    if (num <= silent_ot_left()) {
      for (int i = 0; i < num; i++) data_yz[i] = vole_triples[ot_used+i];
      //memcpy(data_yz, vole_triples + ot_used, num * sizeof(__uint128_t));
      this->ot_used += num;
      return;
    }
    mpz_class *pt = data_yz;
    int gened = silent_ot_left();
    if (gened > 0) {
      //memcpy(pt, vole_triples + ot_used, gened * sizeof(__uint128_t));
      for (int i = 0; i < gened; i++) pt[i] = vole_triples[ot_used+i];
      pt = &pt[gened];
    }
    int round_inplace = (num - gened - M) / ot_limit;
    int last_round_ot = num - gened - round_inplace * ot_limit;
    bool round_memcpy = last_round_ot > ot_limit ? true : false;
    if (round_memcpy)
      last_round_ot -= ot_limit;
    for (int i = 0; i < round_inplace; ++i) {
      extend(pt);
      ot_used = ot_limit;
      pt = &pt[ot_limit];
    }
    if (round_memcpy) {
      extend(&vole_triples[0]);
      for (int i = 0; i < ot_limit; i++) pt[i] = vole_triples[i];
      //memcpy(pt, vole_triples, ot_limit * sizeof(__uint128_t));
      ot_used = ot_limit;
      pt = &pt[ot_limit];
    }
    if (last_round_ot > 0) {
      extend(&vole_triples[0]);
      for (int i = 0; i < last_round_ot; i++) pt[i] = vole_triples[i];
      //memcpy(pt, vole_triples, last_round_ot * sizeof(__uint128_t));
      ot_used = last_round_ot;
    }
  }

  // the version with libOTe
  void extend_sender(osuCrypto::Socket &sock, mpz_class *data_yz, int num) {
    if (vole_triples.size() == 0) vole_triples.resize(param.n);
    if (extend_initialized == false)
      error("Run setup before extending");
    if (num <= silent_ot_left()) {
      for (int i = 0; i < num; i++) data_yz[i] = vole_triples[ot_used+i];
      //memcpy(data_yz, vole_triples + ot_used, num * sizeof(__uint128_t));
      this->ot_used += num;
      return;
    }
    mpz_class *pt = data_yz;
    int gened = silent_ot_left();
    if (gened > 0) {
      //memcpy(pt, vole_triples + ot_used, gened * sizeof(__uint128_t));
      for (int i = 0; i < gened; i++) pt[i] = vole_triples[ot_used+i];
      pt = &pt[gened];
    }
    int round_inplace = (num - gened - M) / ot_limit;
    int last_round_ot = num - gened - round_inplace * ot_limit;
    bool round_memcpy = last_round_ot > ot_limit ? true : false;
    if (round_memcpy)
      last_round_ot -= ot_limit;
    for (int i = 0; i < round_inplace; ++i) {
      extend(sock, pt);
      ot_used = ot_limit;
      pt = &pt[ot_limit];
    }
    if (round_memcpy) {
      extend(sock, &vole_triples[0]);
      for (int i = 0; i < ot_limit; i++) pt[i] = vole_triples[i];
      //memcpy(pt, vole_triples, ot_limit * sizeof(__uint128_t));
      ot_used = ot_limit;
      pt = &pt[ot_limit];
    }
    if (last_round_ot > 0) {
      extend(sock, &vole_triples[0]);
      for (int i = 0; i < last_round_ot; i++) pt[i] = vole_triples[i];
      //memcpy(pt, vole_triples, last_round_ot * sizeof(__uint128_t));
      ot_used = last_round_ot;
    }
  }  

  void extend_recver(mpz_class *data_yz, mpz_class *data_x, int num) {
    if (vole_triples.size() == 0) {
      vole_triples.resize(param.n);
      vole_x.resize(param.n);
    }
    if (extend_initialized == false)
      error("Run setup before extending");
    if (num <= silent_ot_left()) {
      for (int i = 0; i < num; i++) {
        data_yz[i] = vole_triples[ot_used+i];
        data_x[i] = vole_x[ot_used+i];
      }
      //memcpy(data_yz, vole_triples + ot_used, num * sizeof(__uint128_t));
      this->ot_used += num;
      return;
    }
    mpz_class *pt = data_yz;
    mpz_class *pt2 = data_x;
    int gened = silent_ot_left();
    if (gened > 0) {
      //memcpy(pt, vole_triples + ot_used, gened * sizeof(__uint128_t));
      for (int i = 0; i < gened; i++) {
        pt[i] = vole_triples[ot_used+i];
        pt2[i] = vole_x[ot_used+i];
      }
      pt = &pt[gened];
      pt2 = &pt2[gened];
    }
    int round_inplace = (num - gened - M) / ot_limit;
    int last_round_ot = num - gened - round_inplace * ot_limit;
    bool round_memcpy = last_round_ot > ot_limit ? true : false;
    if (round_memcpy)
      last_round_ot -= ot_limit;
    for (int i = 0; i < round_inplace; ++i) {
      extend(pt, pt2);
      ot_used = ot_limit;
      pt = &pt[ot_limit];
      pt2 = &pt2[ot_limit];
    }
    if (round_memcpy) {
      extend(&vole_triples[0], &vole_x[0]);
      for (int i = 0; i < ot_limit; i++) {
        pt[i] = vole_triples[i];
        pt2[i] = vole_x[i];
      }
      //memcpy(pt, vole_triples, ot_limit * sizeof(__uint128_t));
      ot_used = ot_limit;
      pt = &pt[ot_limit];
      pt2 = &pt2[ot_limit];
    }
    if (last_round_ot > 0) {
      extend(&vole_triples[0], &vole_x[0]);
      for (int i = 0; i < last_round_ot; i++) {
        pt[i] = vole_triples[i];
        pt2[i] = vole_x[i];
      }
      //memcpy(pt, vole_triples, last_round_ot * sizeof(__uint128_t));
      ot_used = last_round_ot;      
    }
  }  

  // the version with libOTe
  void extend_recver(osuCrypto::Socket &sock, mpz_class *data_yz, mpz_class *data_x, int num) {
    if (vole_triples.size() == 0) {
      vole_triples.resize(param.n);
      vole_x.resize(param.n);
    }
    if (extend_initialized == false)
      error("Run setup before extending");
    if (num <= silent_ot_left()) {
      for (int i = 0; i < num; i++) {
        data_yz[i] = vole_triples[ot_used+i];
        data_x[i] = vole_x[ot_used+i];
      }
      //memcpy(data_yz, vole_triples + ot_used, num * sizeof(__uint128_t));
      this->ot_used += num;
      return;
    }
    mpz_class *pt = data_yz;
    mpz_class *pt2 = data_x;
    int gened = silent_ot_left();
    if (gened > 0) {
      //memcpy(pt, vole_triples + ot_used, gened * sizeof(__uint128_t));
      for (int i = 0; i < gened; i++) {
        pt[i] = vole_triples[ot_used+i];
        pt2[i] = vole_x[ot_used+i];
      }
      pt = &pt[gened];
      pt2 = &pt2[gened];
    }
    int round_inplace = (num - gened - M) / ot_limit;
    int last_round_ot = num - gened - round_inplace * ot_limit;
    bool round_memcpy = last_round_ot > ot_limit ? true : false;
    if (round_memcpy)
      last_round_ot -= ot_limit;
    for (int i = 0; i < round_inplace; ++i) {
      extend(sock, pt, pt2);
      ot_used = ot_limit;
      pt = &pt[ot_limit];
      pt2 = &pt2[ot_limit];
    }
    if (round_memcpy) {
      extend(sock, &vole_triples[0], &vole_x[0]);
      for (int i = 0; i < ot_limit; i++) {
        pt[i] = vole_triples[i];
        pt2[i] = vole_x[i];
      }
      //memcpy(pt, vole_triples, ot_limit * sizeof(__uint128_t));
      ot_used = ot_limit;
      pt = &pt[ot_limit];
      pt2 = &pt2[ot_limit];
    }
    if (last_round_ot > 0) {
      extend(sock, &vole_triples[0], &vole_x[0]);
      for (int i = 0; i < last_round_ot; i++) {
        pt[i] = vole_triples[i];
        pt2[i] = vole_x[i];
      }
      //memcpy(pt, vole_triples, last_round_ot * sizeof(__uint128_t));
      ot_used = last_round_ot;      
    }
  }  

  // uint64_t extend_inplace(__uint128_t *data_yz, int byte_space) {
  //   if (byte_space < param.n)
  //     error("space not enough");
  //   uint64_t tp_output_n = byte_space - M;
  //   if (tp_output_n % ot_limit != 0)
  //     error("call byte_memory_need_inplace \
	// 			to get the correct length of memory space");
  //   int round = tp_output_n / ot_limit;
  //   __uint128_t *pt = data_yz;
  //   for (int i = 0; i < round; ++i) {
  //     extend(pt);
  //     pt += ot_limit;
  //   }
  //   return tp_output_n;
  // }

  // uint64_t byte_memory_need_inplace(uint64_t tp_need) {
  //   int round = (tp_need - 1) / ot_limit;
  //   return round * ot_limit + param.n;
  // }

  int silent_ot_left() { return ot_limit - ot_used; }

  // debug function
  // void check_triple(__uint128_t x, __uint128_t *y, int size) {
  //   if (party == ALICE) {
  //     io->send_data(&x, sizeof(__uint128_t));
  //     io->send_data(y, size * sizeof(__uint128_t));
  //   } else {
  //     __uint128_t delta;
  //     __uint128_t *k = new __uint128_t[size];
  //     io->recv_data(&delta, sizeof(__uint128_t));
  //     io->recv_data(k, size * sizeof(__uint128_t));
  //     for (int i = 0; i < size; ++i) {
  //       __uint128_t tmp = mod(delta * (y[i] >> 64), pr);
  //       tmp = mod(tmp + k[i], pr);
  //       if (tmp != (y[i] & 0xFFFFFFFFFFFFFFFFLL)) {
  //         std::cout << "triple error at index: " << i << std::endl;
  //         abort();
  //       }
  //     }
  //   }
  // }
};
#endif // _ITERATIVE_COT_H_
