#include <cassert>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <vector>

typedef unsigned char byte;

// EC name
// TODO: Decide which curve to use.
//       224r1 has the least time cost so far.
#define CURVE_NAME NID_secp224r1
// Number of bits in exponent
constexpr int N_BITS = 512;
// Number of iterations for testing
constexpr int N_ITERS = 10000;

EC_GROUP *InitializeCurve() {
  EC_GROUP *curve;

  if ((curve = EC_GROUP_new_by_curve_name(CURVE_NAME)) == nullptr) {
    std::cerr << "ERROR: Curve init failed." << std::endl;
    return nullptr;
  }

  return curve;
}

/* Generate random big numbers. */
std::vector<BIGNUM*> GenRandomBigNums(const int num_iters) {
  std::vector<BIGNUM*> results(num_iters);

  for (int i = 0; i < num_iters; i++) {
    results[i] = BN_new();
    BN_rand(results[i], N_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
  }

  return results;
}

/* Straightforward method for EC computation. */
std::vector<EC_POINT*> BruteForce(
		const EC_GROUP* const curve,
		const std::vector<BIGNUM*>& exponents,
		BN_CTX* ctx) {
  const int N = exponents.size();
  std::vector<EC_POINT*> results;
  results.reserve(N);

  for (int i = 0; i < N; i++) {
    EC_POINT* res = EC_POINT_new(curve);
    assert(EC_POINT_mul(curve, res, exponents[i], nullptr, nullptr, ctx) == 1);
    results.emplace_back(res);
  }

  return results;
}

/* Initialize precomputing results in a 2D table. */
std::vector<std::vector<EC_POINT*>> InitializeDpTable(
		const EC_GROUP* const curve,
		BN_CTX* ctx) {
  constexpr int n_bytes = N_BITS / 8;
  constexpr int n_combs = (int(1) << 8);
  byte exponent[n_bytes];

  std::vector<std::vector<EC_POINT*>> dp(n_bytes,
		  std::vector<EC_POINT*>(n_combs));

  for (int i = 0; i < n_bytes; i++) {
    std::memset(exponent, 0, n_bytes);
    for (int j = 0; j < n_combs; j++) {
      exponent[i] = byte(j);
      dp[i][j] = EC_POINT_new(curve);
      assert(EC_POINT_mul(curve, dp[i][j],
                 BN_bin2bn(exponent, n_bytes, nullptr),
		 nullptr, nullptr, ctx) == 1);
    }
  }

  return dp;
}

/* EC computation using precomputed results. */
std::vector<EC_POINT*> DpMethod(
		const EC_GROUP* const curve,
		const std::vector<BIGNUM*>& exponents,
		const std::vector<std::vector<EC_POINT*>>& dp,
		BN_CTX* ctx) {
  const int N = exponents.size();
  std::vector<EC_POINT*> results;
  results.reserve(N);

  constexpr int n_bytes = N_BITS / 8;
  byte exponent[n_bytes];
  for (int i = 0; i < N; i++) {
    const int len_used = BN_bn2bin(exponents[i], exponent);  // big-endian
    assert(len_used <= n_bytes);
    EC_POINT* res = EC_POINT_new(curve);
    assert(EC_POINT_set_to_infinity(curve, res) == 1);
    for (int j = 0; j < len_used; j++) {
      const int k = j + n_bytes - len_used;
      assert(EC_POINT_add(curve, res, res, dp[k][exponent[j]], ctx) == 1);
    }
    results.emplace_back(res);
  }

  return results;
}

/* Compare results computed by two methods as above. */
bool BigNumVectorCmp(const EC_GROUP* const curve,
		     const std::vector<EC_POINT*>& v,
		     const std::vector<EC_POINT*>& u,
		     BN_CTX* ctx) {
  if (v.size() != u.size()) {
    return false;
  }
  for (int i = 0; i < v.size(); i++) {
    if (EC_POINT_cmp(curve, v[i], u[i], ctx) != 0) {
      return false;
    }
  }
  return true;
}

int main() {
  constexpr int num_iters = N_ITERS;
  const EC_GROUP* curve = InitializeCurve();

  BN_CTX *ctx = BN_CTX_new();
  std::vector<BIGNUM*> exponents = GenRandomBigNums(num_iters);

  auto bf_start = std::chrono::high_resolution_clock::now();
  std::vector<EC_POINT*> bf_results = BruteForce(curve, exponents, ctx);
  auto bf_end = std::chrono::high_resolution_clock::now();

  std::vector<std::vector<EC_POINT*>> dp = InitializeDpTable(curve, ctx);

  auto dp_start = std::chrono::high_resolution_clock::now();
  std::vector<EC_POINT*> dp_results = DpMethod(curve, exponents, dp, ctx);
  auto dp_end = std::chrono::high_resolution_clock::now();

  assert(BigNumVectorCmp(curve, bf_results, dp_results, ctx));

  std::cout << "BF: " <<
	  std::chrono::duration_cast<std::chrono::duration<double>>(
			  bf_end - bf_start).count() << " sec." << std::endl;
  std::cout << "DP: " <<
	  std::chrono::duration_cast<std::chrono::duration<double>>(
			  dp_end - dp_start).count() << " sec." << std::endl;

  return 0;
}

