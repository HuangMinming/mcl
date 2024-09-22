#include <mcl/ecdsa.h>
#include <cybozu/test.hpp>
#include <string.h>
#include <stdint.h>

/*
 “233A464C52” ==>[0x23, 0x3A, 0x46, 0x4C, 0x52]
*/
u_int32_t HexStrToByteStr(const u_char * src_buf, int src_len, u_char * dest_buf)
{
    u_char highByte, lowByte;
    if(NULL == src_buf)
		return 1;
	const u_char * index = src_buf, * end = src_buf + src_len;
    u_char * ridx = dest_buf;
    
    while (index < end)
    {
        highByte = tolower(* (index ++));
        lowByte  = tolower(* (index ++));

        if (highByte > 0x39)
            highByte -= 0x57;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x57;
        else
            lowByte -= 0x30;

        *ridx ++ = (highByte << 4) | lowByte;
    }
	// printf("\n");
	// for(int i=0;i<src_len/2;i++){
	// 	printf("%02x", dest_buf[i]);
	// }
	// printf("\n");
    return 0;
}

template<class T, class Serializer, class Deserializer>
void serializeTest(const T& x, const Serializer& serialize, const Deserializer& deserialize)
{
	uint8_t buf1[128];
	uint8_t buf2[128];
	u_char bufHex[BUFSIZ];
	char bufStr[BUFSIZ];
	memset(bufHex, 0x00, sizeof(bufHex));
	memset(bufStr, 0x00, sizeof(bufStr));
	size_t n = serialize(buf1, sizeof(buf1), &x);
	printf("buf1: (%d bytes)\n", n);
	for(int i=0;i<n;i++) {
		printf("%c", buf1[i]);
	}
	printf("\n");
	for(int i=0;i<n;i++) {
		printf("%02x", buf1[i]);
		sprintf((char*)bufHex + i * 2, "%02x", buf1[i]);
	}
	printf("\n");
	for(int i=0;i<n*2;i++) {
		printf("%c", bufHex[i]);
	}
	printf("\n");
	// HexStrToByteStr(bufHex, 2*n, bufStr);
	// for(int i=0;i<n;i++) {
	// 	printf("%c", bufStr[i]);
	// }
	// printf("\n");

	CYBOZU_TEST_ASSERT(n > 0);
	T y;
	size_t m = deserialize(&y, buf1, n);
	CYBOZU_TEST_EQUAL(m, n);
	size_t n2 = serialize(buf2, sizeof(buf2), &y);
	CYBOZU_TEST_EQUAL(n, n2);
	CYBOZU_TEST_EQUAL_ARRAY(buf1, buf2, n);
}

CYBOZU_TEST_AUTO(ecdsa)
{
	printf("CYBOZU_TEST_AUTO ok0 \n");
	int ret;
	ret = ecdsaInit();
	printf("ret: %d\n", ret);
	CYBOZU_TEST_EQUAL(ret, 0);

	//test
	ecdsaSignature sigTest;
	ecdsaPublicKey pubTest;
	char *sigHexStr = "3045022100bd97bad9e44ec3caeb05dbcc4a3d3a10d1b5380384660db83ae5057afaf019f302204df635a692a26d49424f441f621c511c204bb4d805329c88cd59b8cd54ecb040";
	
	size_t sigHexStrLen = strlen(sigHexStr);
	u_char sigStr[BUFSIZ];
	size_t sigStrLen = sigHexStrLen/2;
	memset(sigStr, 0x00, sizeof(sigStr));
	HexStrToByteStr((const u_char*)sigHexStr, sigHexStrLen, sigStr);
	printf("sigStr: \n");
	for(int i=0;i<sigStrLen;i++)
	{
		printf("%c", sigStr[i]);
	}
	printf("\n");
	for(int i=0;i<sigStrLen;i++)
	{
		printf("%02x", sigStr[i]);
	}
	printf("\n");
	ecdsaSignatureDeserialize(&sigTest, sigStr, sigStrLen);
	const char *pubHexStr = "0461affd4f2a047a602ff2d79acb3249bde5e2963ff1b5042f6539244e0a4bb0ac1664b75d634b57f9417906af1fa79515474ba8422f590e9d7f37841b9f549949";
	size_t pubHexStrLen = strlen(pubHexStr);
	u_char pubStr[BUFSIZ];
	size_t pubStrLen = pubHexStrLen/2;
	HexStrToByteStr((const u_char*)pubHexStr, pubHexStrLen, pubStr);
	printf("pubStr: \n");
	for(int i=0;i<pubStrLen;i++)
	{
		printf("%c", pubStr[i]);
	}
	printf("\n");
	for(int i=0;i<pubStrLen;i++)
	{
		printf("%02x", pubStr[i]);
	}
	printf("\n");
	ecdsaPublicKeyDeserialize(&pubTest, pubStr, pubStrLen);
	const char *msgTest = "abc";
	int iRet = 0;
	iRet = ecdsaVerify(&sigTest, &pubTest, msgTest, strlen(msgTest));
	printf("ecdsaVerify: %d\n", iRet);



	ecdsaSecretKey sec;
	ecdsaPublicKey pub;
	ecdsaPrecomputedPublicKey *ppub;
	ecdsaSignature sig;
	const char *msg = "hello";
	mclSize msgSize = strlen(msg);

	ret = ecdsaSecretKeySetByCSPRNG(&sec);
	CYBOZU_TEST_EQUAL(ret, 0);
	printf("ecdsaSecretKeySerialize: \n");
	serializeTest(sec, ecdsaSecretKeySerialize, ecdsaSecretKeyDeserialize);

	ecdsaGetPublicKey(&pub, &sec);
	printf("ecdsaPublicKeySerialize: \n");
	serializeTest(pub, ecdsaPublicKeySerialize, ecdsaPublicKeyDeserialize);
	ecdsaSign(&sig, &sec, msg, msgSize);
	printf("ecdsaSignatureSerialize: \n");
	serializeTest(sig, ecdsaSignatureSerialize, ecdsaSignatureDeserialize);
	CYBOZU_TEST_ASSERT(ecdsaVerify(&sig, &pub, msg, msgSize));
	ecdsaNormalizeSignature(&sig);
	CYBOZU_TEST_ASSERT(ecdsaVerify(&sig, &pub, msg, msgSize));

	ppub = ecdsaPrecomputedPublicKeyCreate();
	CYBOZU_TEST_ASSERT(ppub);
	ret = ecdsaPrecomputedPublicKeyInit(ppub, &pub);
	CYBOZU_TEST_EQUAL(ret, 0);

	CYBOZU_TEST_ASSERT(ecdsaVerifyPrecomputed(&sig, ppub, msg, msgSize));

	sig.d[0]++;
	CYBOZU_TEST_ASSERT(!ecdsaVerify(&sig, &pub, msg, msgSize));
	CYBOZU_TEST_ASSERT(!ecdsaVerifyPrecomputed(&sig, ppub, msg, msgSize));

	ecdsaPrecomputedPublicKeyDestroy(ppub);
}
