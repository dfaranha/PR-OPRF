#ifndef OPRF_LPN_FP_H__
#define OPRF_LPN_FP_H__

#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-vole/utility.h"
#include <gmpxx.h>
#include "oprf/util/gmp-fp.h"

// note, this program only supports d=10
// TODO: generalize it to any d

namespace emp {
template <int d = 10> class OprfLpnFp {
public:
  int party;
  int k, n;
  ThreadPool *pool;
  int threads;
  block seed;

  mpz_class *M, *X;
  const mpz_class *preM, *preX;

  mpz_class *K;
  const mpz_class *preK;

  uint32_t k_mask;
  OprfLpnFp(int n, int k, ThreadPool *pool, int threads, block seed = zero_block) {
    this->k = k;
    this->n = n;
    this->pool = pool;
    this->threads = threads;
    this->seed = seed;

    k_mask = 1;
    while (k_mask < (uint32_t)k) {
      k_mask <<= 1;
      k_mask = k_mask | 0x1;
    }
  }

  void add2_single(int idx1, int *idx2) {
    for (int j = 0; j < d; j++) {
      M[idx1] += preM[idx2[j]];
      X[idx1] += preX[idx2[j]];
    }
    M[idx1] %= gmp_P;
    X[idx1] %= gmp_P;
  }

  void add2(int idx1, int *idx2) {
    int *p = idx2;
    for (int j = 0; j < d; ++j) {
      X[idx1] += preX[*p]; M[idx1] += preM[*(p++)];
      X[idx1 + 1] += preX[*p]; M[idx1 + 1] += preM[*(p++)];
      X[idx1 + 2] += preX[*p]; M[idx1 + 2] += preM[*(p++)];
      X[idx1 + 3] += preX[*p]; M[idx1 + 3] += preM[*(p++)];
    }
    X[idx1] %= gmp_P;
    X[idx1 + 1] %= gmp_P;
    X[idx1 + 2] %= gmp_P;
    X[idx1 + 3] %= gmp_P;
    M[idx1] %= gmp_P;
    M[idx1 + 1] %= gmp_P;
    M[idx1 + 2] %= gmp_P;
    M[idx1 + 3] %= gmp_P;    
  }

  // sender's procedures

  void add1_single(int idx1, int *idx2) {
    for (int j = 0; j < d; j++) K[idx1] += preK[idx2[j]];
    K[idx1] %= gmp_P;
  }

  void add1(int idx1, int *idx2) {
    int *p = idx2;
    for (int j = 0; j < d; ++j) {
      K[idx1] += preK[*(p++)];
      K[idx1 + 1] += preK[*(p++)];
      K[idx1 + 2] += preK[*(p++)];
      K[idx1 + 3] += preK[*(p++)];
    }
    K[idx1] %= gmp_P;
    K[idx1 + 1] %= gmp_P;
    K[idx1 + 2] %= gmp_P;
    K[idx1 + 3] %= gmp_P;
  }

  void __compute4(int i, PRP *prp, std::function<void(int, int *)> add_func) {
    block tmp[10];
    for (int m = 0; m < 10; ++m)
      tmp[m] = makeBlock(i, m);
    prp->permute_block(tmp, 10);
    int *index = (int *)(tmp);
    for (int j = 0; j < 4 * d; ++j) {
      index[j] = index[j] & k_mask;
      index[j] = index[j] >= k ? index[j] - k : index[j];
    }
    add_func(i, index);
  }

  void __compute1(int i, PRP *prp, std::function<void(int, int *)> add_func) {
    block tmp[3];
    for (int m = 0; m < 3; ++m)
      tmp[m] = makeBlock(i, m);
    prp->permute_block(tmp, 3);
    uint32_t *r = (uint32_t *)(tmp);
    int index[d];
    for (int j = 0; j < d; ++j) {
      index[j] = r[j] & k_mask;
      index[j] = index[j] >= k ? index[j] - k : index[j];
    }
    add_func(i, index);
  }

  void task_send(int start, int end) {
    PRP prp(seed);
    int j = start;
    std::function<void(int, int *)> add_func1 = std::bind(
        &OprfLpnFp::add1, this, std::placeholders::_1, std::placeholders::_2);
    std::function<void(int, int *)> add_func1s =
        std::bind(&OprfLpnFp::add1_single, this, std::placeholders::_1,
                  std::placeholders::_2);
    for (; j < end - 4; j += 4)
      __compute4(j, &prp, add_func1);
    for (; j < end; ++j)
      __compute1(j, &prp, add_func1s);
  }

  void task_recv(int start, int end) {
    PRP prp(seed);
    int j = start;
    std::function<void(int, int *)> add_func2 = std::bind(
        &OprfLpnFp::add2, this, std::placeholders::_1, std::placeholders::_2);
    std::function<void(int, int *)> add_func2s =
        std::bind(&OprfLpnFp::add2_single, this, std::placeholders::_1,
                  std::placeholders::_2);
    for (; j < end - 4; j += 4)
      __compute4(j, &prp, add_func2);
    for (; j < end; ++j)
      __compute1(j, &prp, add_func2s);
  }  

  void compute_send() {
    vector<std::future<void>> fut;
    int width = n / (threads + 1);
    for (int i = 0; i < threads; ++i) {
      int start = i * width;
      int end = min((i + 1) * width, n);
      fut.push_back(pool->enqueue([this, start, end]() { task_send(start, end); }));
    }
    int start = threads * width;
    int end = min((threads + 1) * width, n);
    task_send(start, end);

    for (auto &f : fut)
      f.get();
  }

  void compute_recv() {
    vector<std::future<void>> fut;
    int width = n / (threads + 1);
    for (int i = 0; i < threads; ++i) {
      int start = i * width;
      int end = min((i + 1) * width, n);
      fut.push_back(pool->enqueue([this, start, end]() { task_recv(start, end); }));
    }
    int start = threads * width;
    int end = min((threads + 1) * width, n);
    task_recv(start, end);

    for (auto &f : fut)
      f.get();
  }  

  void compute_send(mpz_class *K, const mpz_class *kkK) {
    this->party = ALICE;
    this->K = K;
    this->preK = kkK;
    compute_send();
  }

  void compute_recv(mpz_class *M, mpz_class *X, const mpz_class *kkM, const mpz_class *kkX) {
    this->party = BOB;
    this->M = M;
    this->X = X;
    this->preM = kkM;
    this->preX = kkX;
    compute_recv();
  }
};
} // namespace emp
#endif
