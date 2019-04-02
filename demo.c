#include <stdio.h>
#include <stdarg.h>
#include <string.h>

	#include "ecdsa.h"
	#include "secp256k1.h"

#define UNUSED(x) (void)(x)
#define BUFSIZ 1024

#ifndef CK_MAX_ASSERT_MEM_PRINT_SIZE
#define CK_MAX_ASSERT_MEM_PRINT_SIZE 64
#endif

#define ck_assert(expr) ck_assert_msg(expr, NULL)

#define ck_assert_msg(expr, ...) \
  (expr) ? \
_mark_point(__func__, __FILE__, __LINE__) : \
_ck_assert_failed(__func__, __FILE__, __LINE__, "Assertion '"#expr"' failed" , ## __VA_ARGS__, NULL)

#define _ck_assert_int(X, OP, Y) do { \
intmax_t _ck_x = (X); \
intmax_t _ck_y = (Y); \
ck_assert_msg(_ck_x OP _ck_y, "Assertion '%s' failed: %s == %jd, %s == %jd", #X" "#OP" "#Y, #X, _ck_x, #Y, _ck_y); \
} while (0)

#define _ck_assert_mem(X, OP, Y, L) do { \
const uint8_t* _ck_x = (const uint8_t*)(X); \
const uint8_t* _ck_y = (const uint8_t*)(Y); \
size_t _ck_l = (L); \
char _ck_x_str[CK_MAX_ASSERT_MEM_PRINT_SIZE * 2 + 1]; \
char _ck_y_str[CK_MAX_ASSERT_MEM_PRINT_SIZE * 2 + 1]; \
static const char _ck_hexdigits[] = "0123456789abcdef"; \
size_t _ck_i; \
size_t _ck_maxl = (_ck_l > CK_MAX_ASSERT_MEM_PRINT_SIZE) ? CK_MAX_ASSERT_MEM_PRINT_SIZE : _ck_l; \
for (_ck_i = 0; _ck_i < _ck_maxl; _ck_i++) { \
    _ck_x_str[_ck_i * 2  ]   = _ck_hexdigits[(_ck_x[_ck_i] >> 4) & 0xF]; \
    _ck_y_str[_ck_i * 2  ]   = _ck_hexdigits[(_ck_y[_ck_i] >> 4) & 0xF]; \
    _ck_x_str[_ck_i * 2 + 1] = _ck_hexdigits[_ck_x[_ck_i] & 0xF]; \
    _ck_y_str[_ck_i * 2 + 1] = _ck_hexdigits[_ck_y[_ck_i] & 0xF]; \
  } \
  _ck_x_str[_ck_i * 2] = 0; \
  _ck_y_str[_ck_i * 2] = 0; \
if (_ck_maxl != _ck_l) { \
    _ck_x_str[_ck_i * 2 - 2] = '.'; \
    _ck_y_str[_ck_i * 2 - 2] = '.'; \
    _ck_x_str[_ck_i * 2 - 1] = '.'; \
    _ck_y_str[_ck_i * 2 - 1] = '.'; \
  } \
ck_assert_msg(0 OP memcmp(_ck_y, _ck_x, _ck_l), \
"Assertion '%s' failed: %s == \"%s\", %s == \"%s\"", #X" "#OP" "#Y, #X, _ck_x_str, #Y, _ck_y_str); \
} while (0)

#define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
#define ck_assert_mem_eq(X, Y, L) _ck_assert_mem(X, ==, Y, L)

void _mark_point(const char *func, const char *file, int line)
{
	printf("test passed, func: %s, file: %s, line: %d\n", func, file, line);
}

void _ck_assert_failed(const char *func, const char *file, int line, const char *expr, ...)
{
	const char *msg;
	va_list ap;
	char buf[BUFSIZ];
	const char *to_send;

	fprintf(stderr, "func: %s, file: %s, line: %d\n", func, file, line);

	va_start(ap, expr);
msg = (const char *)va_arg(ap, char *);
/*
     * If a message was passed, format it with vsnprintf.
     * Otherwise, print the expression as is.
     */
if(msg != NULL)
{
	vsnprintf(buf, BUFSIZ, msg, ap);
        to_send = buf;
}
else
{
	to_send = expr;
} 
va_end(ap);
fprintf(stderr, "%s\n", to_send);
abort();
}

#define FROMHEX_MAXLEN 512

const uint8_t *fromhex(const char *str) {
  static uint8_t buf[FROMHEX_MAXLEN];
  size_t len = strlen(str) / 2;
  if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}

void test_ecdsa_signature() {
  int res;
  uint8_t digest[32];
  uint8_t pubkey[65];
  const ecdsa_curve *curve = &secp256k1;

  // sha2(sha2("\x18Bitcoin Signed Message:\n\x0cHello World!"))
  memcpy(
      digest,
      fromhex(
          "de4e9524586d6fce45667f9ff12f661e79870c4105fa0fb58af976619bb11432"),
      32);
  // r = 2:  Four points should exist
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000020123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 0);
  ck_assert_int_eq(res, 0);
  ck_assert_mem_eq(
      pubkey,
      fromhex(
          "043fc5bf5fec35b6ffe6fd246226d312742a8c296bfa57dd22da509a2e348529b7dd"
          "b9faf8afe1ecda3c05e7b2bda47ee1f5a87e952742b22afca560b29d972fcf"),
      65);
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000020123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 1);
  ck_assert_int_eq(res, 0);
  ck_assert_mem_eq(
      pubkey,
      fromhex(
          "0456d8089137b1fd0d890f8c7d4a04d0fd4520a30b19518ee87bd168ea12ed809032"
          "9274c4c6c0d9df04515776f2741eeffc30235d596065d718c3973e19711ad0"),
      65);
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000020123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 2);
  ck_assert_int_eq(res, 0);
  ck_assert_mem_eq(
      pubkey,
      fromhex(
          "04cee0e740f41aab39156844afef0182dea2a8026885b10454a2d539df6f6df9023a"
          "bfcb0f01c50bef3c0fa8e59a998d07441e18b1c60583ef75cc8b912fb21a15"),
      65);
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000020123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 3);
  ck_assert_int_eq(res, 0);
  ck_assert_mem_eq(
      pubkey,
      fromhex(
          "0490d2bd2e9a564d6e1d8324fc6ad00aa4ae597684ecf4abea58bdfe7287ea4fa729"
          "68c2e5b0b40999ede3d7898d94e82c3f8dc4536a567a4bd45998c826a4c4b2"),
      65);

  memcpy(
      digest,
      fromhex(
          "0000000000000000000000000000000000000000000000000000000000000000"),
      32);
  // r = 7:  No point P with P.x = 7,  but P.x = (order + 7) exists
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000070123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 2);
  ck_assert_int_eq(res, 0);
  ck_assert_mem_eq(
      pubkey,
      fromhex(
          "044d81bb47a31ffc6cf1f780ecb1e201ec47214b651650867c07f13ad06e12a1b040"
          "de78f8dbda700f4d3cd7ee21b3651a74c7661809699d2be7ea0992b0d39797"),
      65);
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000070123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 3);
  ck_assert_int_eq(res, 0);
  ck_assert_mem_eq(
      pubkey,
      fromhex(
          "044d81bb47a31ffc6cf1f780ecb1e201ec47214b651650867c07f13ad06e12a1b0bf"
          "21870724258ff0b2c32811de4c9ae58b3899e7f69662d41815f66c4f2c6498"),
      65);
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000070123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 0);
  ck_assert_int_eq(res, 1);

  memcpy(
      digest,
      fromhex(
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      32);
  // r = 1:  Two points P with P.x = 1,  but P.x = (order + 7) doesn't exist
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000010123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 0);
  ck_assert_int_eq(res, 0);
  ck_assert_mem_eq(
      pubkey,
      fromhex(
          "045d330b2f89dbfca149828277bae852dd4aebfe136982cb531a88e9e7a89463fe71"
          "519f34ea8feb9490c707f14bc38c9ece51762bfd034ea014719b7c85d2871b"),
      65);
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000010123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 1);
  ck_assert_int_eq(res, 0);
  ck_assert_mem_eq(
      pubkey,
      fromhex(
          "049e609c3950e70d6f3e3f3c81a473b1d5ca72739d51debdd80230ae80cab05134a9"
          "4285375c834a417e8115c546c41da83a263087b79ef1cae25c7b3c738daa2b"),
      65);

  // r = 0 is always invalid
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000010123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 2);
  ck_assert_int_eq(res, 1);
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000000123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 0);
  ck_assert_int_eq(res, 1);
  // r >= order is always invalid
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641410123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 0);
  ck_assert_int_eq(res, 1);
  // check that overflow of r is handled
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "000000000000000000000000000000014551231950B75FC4402DA1722FC9BAEE0123"
          "456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
      digest, 2);
  ck_assert_int_eq(res, 1);
  // s = 0 is always invalid
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "00000000000000000000000000000000000000000000000000000000000000020000"
          "000000000000000000000000000000000000000000000000000000000000"),
      digest, 0);
  ck_assert_int_eq(res, 1);
  // s >= order is always invalid
  res = ecdsa_recover_pub_from_sig(
      curve, pubkey,
      fromhex(
          "0000000000000000000000000000000000000000000000000000000000000002ffff"
          "fffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
      digest, 0);
  ck_assert_int_eq(res, 1);
}

void test_pubkey_validity() {
  uint8_t pub_key[65];
  curve_point pub;
  int res;
  const ecdsa_curve *curve = &secp256k1;

  memcpy(
      pub_key,
      fromhex(
          "0226659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37"),
      33);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 1);

  memcpy(
      pub_key,
      fromhex(
          "025b1654a0e78d28810094f6c5a96b8efb8a65668b578f170ac2b1f83bc63ba856"),
      33);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 1);

  memcpy(
      pub_key,
      fromhex(
          "03433f246a12e6486a51ff08802228c61cf895175a9b49ed4766ea9a9294a3c7fe"),
      33);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 1);

  memcpy(
      pub_key,
      fromhex(
          "03aeb03abeee0f0f8b4f7a5d65ce31f9570cef9f72c2dd8a19b4085a30ab033d48"),
      33);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 1);

  memcpy(
      pub_key,
      fromhex(
          "0496e8f2093f018aff6c2e2da5201ee528e2c8accbf9cac51563d33a7bb74a016054"
          "201c025e2a5d96b1629b95194e806c63eb96facaedc733b1a4b70ab3b33e3a"),
      65);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 1);

  memcpy(
      pub_key,
      fromhex(
          "0498010f8a687439ff497d3074beb4519754e72c4b6220fb669224749591dde416f3"
          "961f8ece18f8689bb32235e436874d2174048b86118a00afbd5a4f33a24f0f"),
      65);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 1);

  memcpy(
      pub_key,
      fromhex(
          "04f80490839af36d13701ec3f9eebdac901b51c362119d74553a3c537faff31b17e2"
          "a59ebddbdac9e87b816307a7ed5b826b8f40b92719086238e1bebf19b77a4d"),
      65);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 1);

  memcpy(
      pub_key,
      fromhex(
          "04f80490839af36d13701ec3f9eebdac901b51c362119d74553a3c537faff31b17e2"
          "a59ebddbdac9e87b816307a7ed5b826b8f40b92719086238e1bebf00000000"),
      65);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 0);

  memcpy(
      pub_key,
      fromhex(
          "04f80490839af36d13701ec3f9eebdac901b51c362119d74553a3c537faff31b17e2"
          "a59ebddbdac9e87b816307a7ed5b8211111111111111111111111111111111"),
      65);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 0);

  memcpy(pub_key, fromhex("00"), 1);
  res = ecdsa_read_pubkey(curve, pub_key, &pub);
  ck_assert_int_eq(res, 0);
}

void test_pubkey_uncompress() {
  uint8_t pub_key[65];
  uint8_t uncompressed[65];
  int res;
  const ecdsa_curve *curve = &secp256k1;

  memcpy(
      pub_key,
      fromhex(
          "0226659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37"),
      33);
  res = ecdsa_uncompress_pubkey(curve, pub_key, uncompressed);
  ck_assert_int_eq(res, 1);
  ck_assert_mem_eq(
      uncompressed,
      fromhex(
          "0426659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37b3"
          "cfbad6b39a8ce8cb3a675f53b7b57e120fe067b8035d771fd99e3eba7cf4de"),
      65);

  memcpy(
      pub_key,
      fromhex(
          "03433f246a12e6486a51ff08802228c61cf895175a9b49ed4766ea9a9294a3c7fe"),
      33);
  res = ecdsa_uncompress_pubkey(curve, pub_key, uncompressed);
  ck_assert_int_eq(res, 1);
  ck_assert_mem_eq(
      uncompressed,
      fromhex(
          "04433f246a12e6486a51ff08802228c61cf895175a9b49ed4766ea9a9294a3c7feeb"
          "4c25bcb840f720a16e8857a011e6b91e0ab2d03dbb5f9762844bb21a7b8ca7"),
      65);

  memcpy(
      pub_key,
      fromhex(
          "0496e8f2093f018aff6c2e2da5201ee528e2c8accbf9cac51563d33a7bb74a016054"
          "201c025e2a5d96b1629b95194e806c63eb96facaedc733b1a4b70ab3b33e3a"),
      65);
  res = ecdsa_uncompress_pubkey(curve, pub_key, uncompressed);
  ck_assert_int_eq(res, 1);
  ck_assert_mem_eq(
      uncompressed,
      fromhex(
          "0496e8f2093f018aff6c2e2da5201ee528e2c8accbf9cac51563d33a7bb74a016054"
          "201c025e2a5d96b1629b95194e806c63eb96facaedc733b1a4b70ab3b33e3a"),
      65);

  memcpy(pub_key, fromhex("00"), 1);
  res = ecdsa_uncompress_pubkey(curve, pub_key, uncompressed);
  ck_assert_int_eq(res, 0);
}

void test_codepoints_curve(const ecdsa_curve *curve) {
  int i, j;
  bignum256 a;
  curve_point p, p1;
  for (i = 0; i < 64; i++) {
    for (j = 0; j < 8; j++) {
      bn_zero(&a);
      a.val[(4 * i) / 30] = (uint32_t)(2 * j + 1) << (4 * i % 30);
      bn_normalize(&a);
      // note that this is not a trivial test.  We add 64 curve
      // points in the table to get that particular curve point.
      scalar_multiply(curve, &a, &p);
      ck_assert_mem_eq(&p, &curve->cp[i][j], sizeof(curve_point));
      bn_zero(&p.y);  // test that point_multiply curve, is not a noop
      point_multiply(curve, &a, &curve->G, &p);
      ck_assert_mem_eq(&p, &curve->cp[i][j], sizeof(curve_point));
      // mul 2 test. this should catch bugs
      bn_lshift(&a);
      bn_mod(&a, &curve->order);
      p1 = curve->cp[i][j];
      point_double(curve, &p1);
      // note that this is not a trivial test.  We add 64 curve
      // points in the table to get that particular curve point.
      scalar_multiply(curve, &a, &p);
      ck_assert_mem_eq(&p, &p1, sizeof(curve_point));
      bn_zero(&p.y);  // test that point_multiply curve, is not a noop
      point_multiply(curve, &a, &curve->G, &p);
      ck_assert_mem_eq(&p, &p1, sizeof(curve_point));
    }
  }
}

void test_mult_border_cases_curve(const ecdsa_curve *curve) {
  bignum256 a;
  curve_point p;
  curve_point expected;
  bn_zero(&a);  // a == 0
  scalar_multiply(curve, &a, &p);
  ck_assert(point_is_infinity(&p));
  point_multiply(curve, &a, &p, &p);
  ck_assert(point_is_infinity(&p));
  point_multiply(curve, &a, &curve->G, &p);
  ck_assert(point_is_infinity(&p));

  bn_addi(&a, 1);  // a == 1
  scalar_multiply(curve, &a, &p);
  ck_assert_mem_eq(&p, &curve->G, sizeof(curve_point));
  point_multiply(curve, &a, &curve->G, &p);
  ck_assert_mem_eq(&p, &curve->G, sizeof(curve_point));

  bn_subtract(&curve->order, &a, &a);  // a == -1
  expected = curve->G;
  bn_subtract(&curve->prime, &expected.y, &expected.y);
  scalar_multiply(curve, &a, &p);
  ck_assert_mem_eq(&p, &expected, sizeof(curve_point));
  point_multiply(curve, &a, &curve->G, &p);
  ck_assert_mem_eq(&p, &expected, sizeof(curve_point));

  bn_subtract(&curve->order, &a, &a);
  bn_addi(&a, 1);  // a == 2
  expected = curve->G;
  point_add(curve, &expected, &expected);
  scalar_multiply(curve, &a, &p);
  ck_assert_mem_eq(&p, &expected, sizeof(curve_point));
  point_multiply(curve, &a, &curve->G, &p);
  ck_assert_mem_eq(&p, &expected, sizeof(curve_point));

  bn_subtract(&curve->order, &a, &a);  // a == -2
  expected = curve->G;
  point_add(curve, &expected, &expected);
  bn_subtract(&curve->prime, &expected.y, &expected.y);
  scalar_multiply(curve, &a, &p);
  ck_assert_mem_eq(&p, &expected, sizeof(curve_point));
  point_multiply(curve, &a, &curve->G, &p);
  ck_assert_mem_eq(&p, &expected, sizeof(curve_point));
}

void test_scalar_mult_curve(const ecdsa_curve *curve) {
  int i;
  // get two "random" numbers
  bignum256 a = curve->G.x;
  bignum256 b = curve->G.y;
  curve_point p1, p2, p3;
  for (i = 0; i < 1000; i++) {
    /* test distributivity: (a + b)G = aG + bG */
    bn_mod(&a, &curve->order);
    bn_mod(&b, &curve->order);
    scalar_multiply(curve, &a, &p1);
    scalar_multiply(curve, &b, &p2);
    bn_addmod(&a, &b, &curve->order);
    bn_mod(&a, &curve->order);
    scalar_multiply(curve, &a, &p3);
    point_add(curve, &p1, &p2);
    ck_assert_mem_eq(&p2, &p3, sizeof(curve_point));
    // new "random" numbers
    a = p3.x;
    b = p3.y;
  }
}

void test_point_mult_curve(const ecdsa_curve *curve) {
  int i;
  // get two "random" numbers and a "random" point
  bignum256 a = curve->G.x;
  bignum256 b = curve->G.y;
  curve_point p = curve->G;
  curve_point p1, p2, p3;
  for (i = 0; i < 200; i++) {
    /* test distributivity: (a + b)P = aP + bP */
    bn_mod(&a, &curve->order);
    bn_mod(&b, &curve->order);
    point_multiply(curve, &a, &p, &p1);
    point_multiply(curve, &b, &p, &p2);
    bn_addmod(&a, &b, &curve->order);
    bn_mod(&a, &curve->order);
    point_multiply(curve, &a, &p, &p3);
    point_add(curve, &p1, &p2);
    ck_assert_mem_eq(&p2, &p3, sizeof(curve_point));
    // new "random" numbers and a "random" point
    a = p1.x;
    b = p1.y;
    p = p3;
  }
}

void test_scalar_point_mult_curve(const ecdsa_curve *curve) {
  int i;
  // get two "random" numbers
  bignum256 a = curve->G.x;
  bignum256 b = curve->G.y;
  curve_point p1, p2;
  for (i = 0; i < 200; i++) {
    /* test commutativity and associativity:
     * a(bG) = (ab)G = b(aG)
     */
    bn_mod(&a, &curve->order);
    bn_mod(&b, &curve->order);
    scalar_multiply(curve, &a, &p1);
    point_multiply(curve, &b, &p1, &p1);

    scalar_multiply(curve, &b, &p2);
    point_multiply(curve, &a, &p2, &p2);

    ck_assert_mem_eq(&p1, &p2, sizeof(curve_point));

    bn_multiply(&a, &b, &curve->order);
    bn_mod(&b, &curve->order);
    scalar_multiply(curve, &b, &p2);

    ck_assert_mem_eq(&p1, &p2, sizeof(curve_point));

    // new "random" numbers
    a = p1.x;
    b = p1.y;
  }
}

int main(void)
{
	test_ecdsa_signature();
	test_pubkey_validity();
	test_pubkey_uncompress();
	test_codepoints_curve(&secp256k1);
	test_mult_border_cases_curve(&secp256k1);
	test_scalar_mult_curve(&secp256k1);
	test_point_mult_curve(&secp256k1);
	test_scalar_point_mult_curve(&secp256k1);

	printf("all tests passed.\n");

	return 0;
}
