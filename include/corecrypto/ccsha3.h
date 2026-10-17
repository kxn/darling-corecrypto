#ifndef _CORECRYPTO_CCSHA3_H_
#define _CORECRYPTO_CCSHA3_H_
#include <corecrypto/ccdigest.h>
const struct ccdigest_info *ccsha3_224_di(void);
const struct ccdigest_info *ccsha3_256_di(void);
const struct ccdigest_info *ccsha3_384_di(void);
const struct ccdigest_info *ccsha3_512_di(void);
#endif
