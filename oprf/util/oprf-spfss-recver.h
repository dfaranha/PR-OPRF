#ifndef OPRF_SPFSS_RECVER_FP_H__
#define OPRF_SPFSS_RECVER_FP_H__
#include "emp-zk/emp-vole/utility.h"
#include "oprf/util/gmp-fp.h"
#include "oprf/util/gmp-prg-fp.h"
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>
#include <iostream>
#include <vector>

using namespace emp;

template <typename IO> class OprfSpfssRecverFp {
public:
  block *ggm_tree, *m;
  __uint128_t *ggm_tree_int;
  bool *b;
  int choice_pos, depth, leave_n;
  IO *io;
  mpz_class share;
  mpz_class choice_beta;
  mpz_class *last_layer;

  OprfSpfssRecverFp(IO *io, int depth_in) {
    this->io = io;
    this->depth = depth_in;
    this->leave_n = 1 << (depth_in - 1);
    m = new block[depth - 1];
    b = new bool[depth - 1];
  }

  ~OprfSpfssRecverFp() {
    delete[] m;
    delete[] b;
  }

  int get_index() {
    choice_pos = 0;
    for (int i = 0; i < depth - 1; ++i) {
      choice_pos <<= 1;
      if (!b[i])
        choice_pos += 1;
    }
    return choice_pos;
  }

  // receive the message and reconstruct the tree
  // j: position of the secret, begins from 0
  template <typename OT> void recv(OT *ot, IO *io2, int s) {
    ot->recv(m, b, depth - 1, io2, s);
    std::vector<uint8_t> vvv(48);
    io2->recv_data(&vvv[0], 48);
    share = hex_compose(&vvv[0]);
  }

  // receive the message and reconstruct the tree
  // j: position of the secret, begins from 0
  // delta2 only use low 64 bits
  void compute(__uint128_t *ggm_tree_mem, mpz_class *last, const mpz_class &delta2) {
    ggm_tree_int = ggm_tree_mem;
    this->ggm_tree = (block *)ggm_tree_mem;
    last_layer = last;
    ggm_tree_reconstruction(b, m);
    ggm_tree[choice_pos] = zero_block;

    // last_layer.resize(leave_n);
    mpz_class nodes_sum = 0;
    for (int i = 0; i < leave_n; ++i) {
      if (i == choice_pos) continue;
      GMP_PRG_FP layer_prg(&ggm_tree[i]);
      last_layer[i] = layer_prg.sample();
      nodes_sum += last_layer[i];
    }
    nodes_sum = (nodes_sum + share) % gmp_P;
    nodes_sum = gmp_P - nodes_sum;
    last_layer[choice_pos] = (delta2 + nodes_sum) % gmp_P;
  }

  void ggm_tree_reconstruction(bool *b, block *m) {
    int to_fill_idx = 0;
    TwoKeyPRP prp(zero_block, makeBlock(0, 1));
    for (int i = 1; i < depth; ++i) {
      to_fill_idx = to_fill_idx * 2;
      ggm_tree[to_fill_idx] = ggm_tree[to_fill_idx + 1] = zero_block;
      if (b[i - 1] == false) {
        layer_recover(i, 0, to_fill_idx, m[i - 1], &prp);
        to_fill_idx += 1;
      } else
        layer_recover(i, 1, to_fill_idx + 1, m[i - 1], &prp);
    }
  }

  void layer_recover(int depth, int lr, int to_fill_idx, block sum,
                     TwoKeyPRP *prp) {
    int layer_start = 0;
    int item_n = 1 << depth;
    block nodes_sum = zero_block;
    int lr_start = lr == 0 ? layer_start : (layer_start + 1);

    for (int i = lr_start; i < item_n; i += 2)
      nodes_sum = nodes_sum ^ ggm_tree[i];
    ggm_tree[to_fill_idx] = nodes_sum ^ sum;
    if (depth == this->depth - 1)
      return;
    for (int i = item_n - 2; i >= 0; i -= 2)
      prp->node_expand_2to4(&ggm_tree[i * 2], &ggm_tree[i]);
  }

  void consistency_check_msg_gen(mpz_class &chi_alpha, mpz_class &W, const mpz_class &beta, block seed) {
    choice_beta = beta;

    GMP_PRG_FP chalprg(&seed);
    mpz_class chal = chalprg.sample();    

    std::vector<mpz_class> chi(leave_n);
    chi[0] = chal;
    for (int i = 1; i < leave_n; i++) chi[i] = chi[i-1] * chal % gmp_P;

    chi_alpha = chi[choice_pos];
    W = 0;
    for (int i = 0; i < leave_n; i++) W += chi[i] * last_layer[i];
    W %= gmp_P;
  }

  // correctness check
  void correctness_check(IO *io2, mpz_class beta) {
    std::vector<uint8_t> vvv(48);
    hex_decompose(beta, &vvv[0]);
    io2->send_data(&vvv[0], 48);
    io2->send_data(&choice_pos, sizeof(int));
    io2->flush();

    for (int i = 0; i < leave_n; i++) {
      for (int j = 0; j < 48; j++) vvv[j] = 0;
      hex_decompose(last_layer[i], &vvv[0]);
      io2->send_data(&vvv[0], 48);
      io2->flush();
    }

  }
};
#endif
