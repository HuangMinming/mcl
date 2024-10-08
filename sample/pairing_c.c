#include <stdio.h>
#include <string.h>
#include <mcl/bn_c384_256.h>

int g_err = 0;
#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); g_err++; } }

int main()
{
	char buf[1600];
	const char *aStr = "123";
	const char *bStr = "456";
	int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret != 0) {
		printf("err ret=%d\n", ret);
		return 1;
	}
	mclBnFr a, b, ab;
	mclBnG1 P, aP;
	mclBnG2 Q, bQ;
	mclBnGT e, e1, e2;
	mclBnFr_setStr(&a, aStr, strlen(aStr), 10);
	mclBnFr_setStr(&b, bStr, strlen(bStr), 10);
	mclBnFr_mul(&ab, &a, &b);
	mclBnFr_getStr(buf, sizeof(buf), &ab, 10);
	printf("%s x %s = %s\n", aStr, bStr, buf);
	mclBnFr_sub(&a, &a, &b);
	mclBnFr_getStr(buf, sizeof(buf), &a, 10);
	printf("%s - %s = %s\n", aStr, bStr, buf);

	ASSERT(!mclBnG1_hashAndMapTo(&P, "this", 4));
	ASSERT(!mclBnG2_hashAndMapTo(&Q, "that", 4));
	ASSERT(mclBnG1_getStr(buf, sizeof(buf), &P, 16));
	printf("P = %s\n", buf);
	ASSERT(mclBnG2_getStr(buf, sizeof(buf), &Q, 16));
	printf("Q = %s\n", buf);

	size_t len = 0;
	len = mclBnG1_serialize(buf, sizeof(buf), &P);
	printf("serialize P(size=%d) =:\n", len);
	for(int i=0;i<len;i++) {
		printf("%d,", (unsigned char)buf[i]);
	}
	printf("\n");
	int iEqual = 0;
	mclBnG1 pp;
	mclBnG1_deserialize(&pp, buf, len);
	iEqual = mclBnG1_isEqual(&P, &pp);
	printf("mclBnG1_isEqual(&P, &pp)=%d \n", iEqual);

	len = mclBnG2_serialize(buf, sizeof(buf), &Q);
	printf("serialize Q(size=%d) =:\n", len);
	for(int i=0;i<len;i++) {
		printf("%d,", (unsigned char)buf[i]);
	}
	printf("\n");
	iEqual = 0;
	mclBnG2 qq;
	mclBnG2_deserialize(&qq, buf, len);
	iEqual = mclBnG2_isEqual(&Q, &qq);
	printf("mclBnG1_isEqual(&Q, &qq)=%d \n", iEqual);

	mclBnG1_mul(&aP, &P, &a);
	mclBnG2_mul(&bQ, &Q, &b);

	mclBn_pairing(&e, &P, &Q);
	ASSERT(mclBnGT_getStr(buf, sizeof(buf), &e, 16));
	printf("e = %s\n", buf);
	len = mclBnGT_serialize(buf, sizeof(buf), &e);
	printf("serialize e(size=%d) =:\n", len);
	for(int i=0;i<len;i++) {
		printf("%d,", (unsigned char)buf[i]);
	}
	printf("\n");
	iEqual = 0;
	mclBnGT ee;
	mclBnGT_deserialize(&ee, buf, len);
	iEqual = mclBnGT_isEqual(&e, &ee);
	printf("mclBnG1_isEqual(&e, &ee)=%d \n", iEqual);
	mclBnGT_pow(&e1, &e, &a);
	mclBn_pairing(&e2, &aP, &Q);
	ASSERT(mclBnGT_isEqual(&e1, &e2));

	mclBnGT_pow(&e1, &e, &b);
	mclBn_pairing(&e2, &P, &bQ);
	ASSERT(mclBnGT_isEqual(&e1, &e2));
	if (g_err) {
		printf("err %d\n", g_err);
		return 1;
	} else {
		printf("no err\n");
		return 0;
	}
}
