#ifndef OPRF_MPFSS_REG_FP_H__
#define OPRF_MPFSS_REG_FP_H__

#include "emp-zk/emp-vole/preot.h"
#include "emp-zk/emp-vole/utility.h"
#include "oprf/oprf.h"
#include <emp-tool/emp-tool.h>
#include <set>

using namespace emp;

template <typename IO> class OprfMpfssRegFp {
public:
  int party;
  int threads;
  int item_n, idx_max, m;
  int tree_height, leave_n;
  int tree_n;
  bool is_malicious;

  PRG prg;
  IO *netio;
  IO **ios;
  mpz_class secret_share_x;
  __uint128_t **ggm_tree;
  mpz_class **ggm_tree_last;
  __uint128_t *check_chialpha_buf = nullptr, *check_VW_buf = nullptr;
  mpz_class *triple_yz;
  ThreadPool *pool;
  std::vector<uint32_t> item_pos_recver;

  OprfMpfssRegFp(int party, int threads, int n, int t, int log_bin_sz,
             ThreadPool *pool, IO **ios) {
    this->party = party;
    this->threads = threads;
    this->netio = ios[0];
    this->ios = ios;

    this->pool = pool;
    this->is_malicious = false;

    // make sure n = t * leave_n
    this->item_n = t;
    this->idx_max = n;
    this->tree_height = log_bin_sz + 1;
    this->leave_n = 1 << (this->tree_height - 1);
    this->tree_n = this->item_n;

    this->ggm_tree =
        (__uint128_t **)malloc(this->item_n * sizeof(__uint128_t *));
    this->ggm_tree_last =
        (mpz_class **)malloc(this->item_n * sizeof(mpz_class *));

    if (party == BOB)
      check_chialpha_buf = new __uint128_t[item_n];
    check_VW_buf = new __uint128_t[item_n];
  }

  ~OprfMpfssRegFp() {
    free(ggm_tree);
    free(ggm_tree_last);
    if (check_chialpha_buf != nullptr)
      delete[] check_chialpha_buf;
    delete[] check_VW_buf;
  }

  void set_malicious() { is_malicious = true; }

  void sender_init(const mpz_class &delta) { secret_share_x = delta; }

  void recver_init() { item_pos_recver.resize(this->item_n); }

//   void set_vec_x(__uint128_t *out, __uint128_t *in) {
//     for (int i = 0; i < tree_n; ++i) {
//       int64_t pt = (int64_t)i * leave_n + ((int64_t)item_pos_recver[i] % leave_n);
//       out[pt] = out[pt] ^ (__uint128_t)makeBlock(in[i], 0x0LL);
//     }
//   }

  void mpfss(OTPre<IO> *ot, mpz_class *triple_yz,
             __uint128_t *sparse_vector, mpz_class *sparse_last_vector) {
    this->triple_yz = triple_yz;
    mpfss(ot, sparse_vector, sparse_last_vector);
  }

  void mpfss(OTPre<IO> *ot, __uint128_t *sparse_vector, mpz_class *sparse_last_vector) {
    vector<OprfSpfssSenderFp<IO> *> senders;
    vector<OprfSpfssRecverFp<IO> *> recvers;
    vector<future<void>> fut;
    for (int i = 0; i < tree_n; ++i) {
      if (party == 1) {
        senders.push_back(new OprfSpfssSenderFp<IO>(netio, tree_height));
        ot->choices_sender();
      } else {
        recvers.push_back(new OprfSpfssRecverFp<IO>(netio, tree_height));
        ot->choices_recver(recvers[i]->b);
        item_pos_recver[i] = recvers[i]->get_index();
      }
    }
    netio->flush();
    ot->reset();

    uint32_t width = tree_n / threads;
    uint32_t start = 0, end = width;
    for (int i = 0; i < threads - 1; ++i) {
      fut.push_back(pool->enqueue(
          [this, start, end, width, senders, recvers, ot, sparse_vector, sparse_last_vector]() {
            for (auto i = start; i < end; ++i) {
              if (party == ALICE) {
                ggm_tree[i] = sparse_vector + i * leave_n;
                ggm_tree_last[i] = sparse_last_vector + i * leave_n;
                senders[i]->compute(ggm_tree[i], ggm_tree_last[i], secret_share_x, triple_yz[i]);
                senders[i]->template send<OTPre<IO>>(ot, ios[start / width], i);
                ios[start / width]->flush();
              } else {
                recvers[i]->template recv<OTPre<IO>>(ot, ios[start / width], i);
                ggm_tree[i] = sparse_vector + i * leave_n;
                ggm_tree_last[i] = sparse_last_vector + i * leave_n;
                recvers[i]->compute(ggm_tree[i], ggm_tree_last[i], triple_yz[i]);
                ios[start / width]->flush();
              }
            }
          }));
      start = end;
      end += width;
    }
    end = tree_n;
    for (auto i = start; i < end; ++i) {
      if (party == ALICE) {
        ggm_tree[i] = sparse_vector + i * leave_n;
        ggm_tree_last[i] = sparse_last_vector + i * leave_n;
        senders[i]->compute(ggm_tree[i], ggm_tree_last[i], secret_share_x, triple_yz[i]);
        senders[i]->template send<OTPre<IO>>(ot, ios[threads - 1], i);
        ios[threads - 1]->flush();
      } else {
        recvers[i]->template recv<OTPre<IO>>(ot, ios[threads - 1], i);
        ggm_tree[i] = sparse_vector + i * leave_n;
        ggm_tree_last[i] = sparse_last_vector + i * leave_n;
        recvers[i]->compute(ggm_tree[i], ggm_tree_last[i], triple_yz[i]);
        ios[threads - 1]->flush();
      }
    }
    for (auto &f : fut)
      f.get();

    // if (is_malicious) {
    //   block *seed = new block[threads];
    //   seed_expand(seed, threads);
    //   vector<future<void>> fut;
    //   uint32_t start = 0, end = width;
    //   for (int i = 0; i < threads - 1; ++i) {
    //     fut.push_back(
    //         pool->enqueue([this, start, end, width, senders, recvers, seed]() {
    //           for (auto i = start; i < end; ++i) {
    //             if (party == ALICE) {
    //               senders[i]->consistency_check_msg_gen(
    //                   check_VW_buf[i], ios[start / width], seed[start / width]);
    //             } else {
    //               recvers[i]->consistency_check_msg_gen(
    //                   check_chialpha_buf[i], check_VW_buf[i],
    //                   ios[start / width], triple_yz[i], seed[start / width]);
    //             }
    //           }
    //         }));
    //     start = end;
    //     end += width;
    //   }
    //   end = tree_n;
    //   for (auto i = start; i < end; ++i) {
    //     if (party == ALICE) {
    //       senders[i]->consistency_check_msg_gen(
    //           check_VW_buf[i], ios[threads - 1], seed[threads - 1]);
    //     } else {
    //       recvers[i]->consistency_check_msg_gen(
    //           check_chialpha_buf[i], check_VW_buf[i], ios[threads - 1],
    //           triple_yz[i], seed[threads - 1]);
    //     }
    //   }
    //   for (auto &f : fut)
    //     f.get();
    //   delete[] seed;
    // }

    // if (is_malicious) {
    //   if (party == ALICE)
    //     consistency_batch_check(triple_yz[tree_n], tree_n);
    //   else
    //     consistency_batch_check(triple_yz, triple_yz[tree_n], tree_n);
    // }

    for (auto p : senders)
      delete p;
    for (auto p : recvers)
      delete p;
  }

  void seed_expand(block *seed, int threads) {
    block sd = zero_block;
    if (party == ALICE) {
      netio->recv_data(&sd, sizeof(block));
    } else {
      prg.random_block(&sd, 1);
      netio->send_data(&sd, sizeof(block));
      netio->flush();
    }
    PRG prg2(&sd);
    prg2.random_block(seed, threads);
  }

//   void consistency_batch_check(__uint128_t y, int num) {
//     uint64_t x_star;
//     netio->recv_data(&x_star, sizeof(uint64_t));
//     uint64_t tmp = mult_mod(secret_share_x, x_star);
//     tmp = add_mod((uint64_t)y, tmp);
//     uint64_t vb = pr - tmp; // y_star

//     for (int i = 0; i < num; ++i)
//       vb = add_mod(vb, (uint64_t)check_VW_buf[i]);
//     Hash hash;
//     block h = hash.hash_for_block(&vb, sizeof(uint64_t));
//     netio->send_data(&h, sizeof(block));
//     netio->flush();
//   }

//   void consistency_batch_check(__uint128_t *delta2, __uint128_t z, int num) {
//     uint64_t beta_mul_chialpha = (uint64_t)0;
//     for (int i = 0; i < num; ++i) {
//       uint64_t tmp = mult_mod(_mm_extract_epi64((block)delta2[i], 1),
//                               check_chialpha_buf[i]);
//       beta_mul_chialpha = add_mod(beta_mul_chialpha, tmp);
//     }
//     uint64_t x_star = PR - beta_mul_chialpha;
//     x_star = add_mod(_mm_extract_epi64((block)z, 1), x_star);
//     netio->send_data(&x_star, sizeof(uint64_t));
//     netio->flush();

//     uint64_t va = PR - _mm_extract_epi64((block)z, 0);
//     for (int i = 0; i < num; ++i)
//       va = mod(va + check_VW_buf[i], pr);

//     Hash hash;
//     block h = hash.hash_for_block(&va, sizeof(uint64_t));
//     block r;
//     netio->recv_data(&r, sizeof(block));
//     if (!cmpBlock(&r, &h, 1))
//       error("MPFSS batch check fails");
//   }

  // debug -- sender
  void check_correctness_sender(IO *io2) {
    std::vector<uint8_t> ext(48);
    hex_decompose(secret_share_x, &ext[0]);
    io2->send_data(&ext[0], 48);
    io2->flush();

    cout << secret_share_x << endl;
    
    for (int i = 0; i < tree_n; i++) {
      for (int j = 0; j < leave_n; j++) {
        for (int t = 0; t < 48; t++) ext[t] = 0;
        hex_decompose(ggm_tree_last[i][j], &ext[0]);
        io2->send_data(&ext[0], 48);
        io2->flush();
      }
    }
  }

  // debug -- recver
  void check_correctness_recver(IO *io2, mpz_class *beta) {    
    std::vector<uint8_t> ext(48);
    io2->recv_data(&ext[0], 48);
    mpz_class delta = hex_compose(&ext[0]);

    for (int i = 0; i < tree_n; i++) {
      for (int j = 0; j < leave_n; j++) {
        io2->recv_data(&ext[0], 48);
        mpz_class V = hex_compose(&ext[0]);
        if (j == item_pos_recver[i]) {
          if ((beta[i] * delta + V) % gmp_P != ggm_tree_last[i][j]) {
            cout << "wrong in hot "  << i << ' ' << j << endl;
            cout << beta[i] << ' ' << delta << ' ' << V << ' ' << ggm_tree_last[i][j] << endl;
            abort();
          }
        } else {
          if (V != ggm_tree_last[i][j]) {
            cout << "wrong in non-hot " << i << ' ' << j << endl;
            abort();
          }
        }
      }
    }
    cout << "check pass" << endl;
  }

};
#endif
