/*
 * Copyright (c) 2012 Apple Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

// #define COMMON_DH_FUNCTIONS
#include <AssertMacros.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonDH.h>
#include <CommonCrypto/CommonRandomSPI.h>
#include "ccDispatch.h"
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>
#include "ccErrors.h"
#include "ccGlobals.h"
#include "ccdebug.h"

typedef struct CCDHParameters_s {
    ccdh_const_gp_t gp;
    size_t malloced;   // bytes of gp storage this set owns, 0 when gp is not ours
    bool stockCopy;    // a private copy made by CCDHCreate for a stock group
} CCDHParmSetstruct, *CCDHParmSet; 

typedef struct DH_ {
	CCDHParmSet parms;
    ccdh_full_ctx_t ctx;
} CCDHstruct, *CCDH;


static void kCCDHRFC2409Group2_storage(void) {}
static void kCCDHRFC3526Group5_storage(void) {}
const CCDHParameters kCCDHRFC2409Group2 = (CCDHParameters)&kCCDHRFC2409Group2_storage;
const CCDHParameters kCCDHRFC3526Group5 = (CCDHParameters)&kCCDHRFC3526Group5_storage;

CCDHRef
CCDHCreate(CCDHParameters dhParameter)
{
    CCDHParmSet CCDHParm = (CCDHParmSet)dhParameter;
    CCDHParmSet stockParm = NULL;
    CCDH retval = NULL;
    size_t retSize = 0;
    
    CC_DEBUG_LOG("Entering\n");
    CC_NONULLPARMRETNULL(dhParameter);
    if (dhParameter == kCCDHRFC2409Group2) {
        require((stockParm = malloc(sizeof(CCDHParmSetstruct))) != NULL, error);
        stockParm->gp = ccdh_gp_rfc2409group02();
        stockParm->malloced = 0;
        stockParm->stockCopy = true;
        CCDHParm = stockParm;
    } else if (dhParameter == kCCDHRFC3526Group5) {
        require((stockParm = malloc(sizeof(CCDHParmSetstruct))) != NULL, error);
        stockParm->gp = ccdh_gp_rfc3526group05();
        stockParm->malloced = 0;
        stockParm->stockCopy = true;
        CCDHParm = stockParm;
    }

    retval = malloc(sizeof(CCDHstruct));
    if(retval == NULL) goto error;
    
    retSize = ccdh_full_ctx_size(ccdh_ccn_size(CCDHParm->gp));
    retval->ctx = malloc(retSize);

    if(retval->ctx == NULL) goto error;
    ccdh_ctx_init(CCDHParm->gp, ccdh_ctx_public(retval->ctx));
    retval->parms = CCDHParm;
        
    return (CCDHRef) retval;

error:
    if(stockParm) free(stockParm);
    if(retval) free(retval);
    return NULL;
}

void
CCDHRelease(CCDHRef ref)
{
    CC_DEBUG_LOG("Entering\n");
    if(ref == NULL) return;
    CCDH keyref = (CCDH) ref;
    if(keyref->ctx)
        free(keyref->ctx);
    keyref->ctx = NULL;
    // Only the copy of a stock group made by CCDHCreate belongs to the context; parameters
    // created with CCDHParametersCreateFromData stay with their caller.
    if(keyref->parms && keyref->parms->stockCopy) free(keyref->parms);
    keyref->parms = NULL;
    free(keyref);
}

int
CCDHGenerateKey(CCDHRef ref, void *output, size_t *outputLength)
{
    CC_DEBUG_LOG("Entering\n");
    CC_NONULLPARM(ref);
    CC_NONULLPARM(output);
    CC_NONULLPARM(outputLength);
    
    CCDH keyref = (CCDH) ref;
    
    if(ccdh_generate_key(keyref->parms->gp, ccDRBGGetRngState(), keyref->ctx))
        return -1;
    
    size_t size_needed = ccdh_export_pub_size(ccdh_ctx_public(keyref->ctx));
    if(size_needed > *outputLength) {
        *outputLength = size_needed;
        return -1;
    }
    
    *outputLength = size_needed;
    ccdh_export_pub(ccdh_ctx_public(keyref->ctx), output);
    return 0;
}


int
CCDHComputeKey(unsigned char *sharedKey, size_t *sharedKeyLen, const void *peerPubKey, size_t peerPubKeyLen, CCDHRef ref)
{
    CC_DEBUG_LOG("Entering\n");
    CC_NONULLPARM(sharedKey);
    CC_NONULLPARM(sharedKeyLen);
    CC_NONULLPARM(peerPubKey);
    CC_NONULLPARM(ref);
    
    CCDH keyref = (CCDH) ref;
    ccdh_pub_ctx_decl_gp(keyref->parms->gp, peer_pub);
    
    // Return the expected value in case of error
    size_t size_needed = CC_BITLEN_TO_BYTELEN(ccdh_gp_prime_bitlen(keyref->parms->gp));
    if (size_needed > *sharedKeyLen) {
        *sharedKeyLen = size_needed;
        return -1;
    }

    // Import key
    if (ccdh_import_pub(keyref->parms->gp, peerPubKeyLen, peerPubKey,
                       peer_pub)) {
        *sharedKeyLen = size_needed;
        return -2;
    }
    
    // Export secret with no leading zero
    if (ccdh_compute_shared_secret(keyref->ctx, peer_pub, sharedKeyLen,sharedKey,ccrng(NULL))) {
        return -3;
    }

    return 0;

}

CCDHParameters
CCDHParametersCreateFromData(const void *p, size_t pLen, const void *g, size_t gLen, size_t l)
{
    CC_DEBUG_LOG("Entering\n");
    CC_NONULLPARMRETNULL(p);
    CC_NONULLPARMRETNULL(g);

    // p and g are big-endian unsigned integers; leading zero bytes carry no value.
    const uint8_t *pb = p, *gb = g;
    while (pLen > 0 && *pb == 0) { pb++; pLen--; }
    while (gLen > 0 && *gb == 0) { gb++; gLen--; }

    // The modulus must be odd and at least 3, the generator in [2, p-1], and the
    // private value length (in bits, 0 meaning unspecified) must fit in the modulus.
    if (pLen == 0 || gLen == 0) return NULL;
    if ((pb[pLen - 1] & 1) == 0) return NULL;
    if (pLen == 1 && pb[0] < 3) return NULL;
    if (gLen == 1 && gb[0] < 2) return NULL;
    if (gLen > pLen || (gLen == pLen && memcmp(gb, pb, pLen) >= 0)) return NULL;
    if (l > pLen * 8) return NULL;

    cc_size n = ccn_nof_size(pLen);
    cc_unit pval[n], gval[n];
    if (ccn_read_uint(n, pval, pLen, pb) || ccn_read_uint(n, gval, gLen, gb)) return NULL;

    CCDHParmSet retval = malloc(sizeof(CCDHParmSetstruct));
    if(!retval) return NULL;

    retval->stockCopy = false;
    // ccdh_gp_size takes the size of the prime in bytes, not in units.
    retval->malloced = ccdh_gp_size(ccn_sizeof_n(n));
    retval->gp = malloc(retval->malloced);
    if(retval->gp==NULL) goto error;
    if(ccdh_init_gp((ccdh_gp_t)retval->gp, n, pval, gval, (cc_size) l)) //const is discarded in retval->gp
        goto error;
    return retval;
error:
    if(retval->gp) free((ccdh_gp_t)retval->gp); //const is discarded in retval->gp
    free(retval);
    return NULL;
}

void
CCDHParametersRelease(CCDHParameters parameters)
{
    CC_DEBUG_LOG("Entering\n");
    if(parameters == NULL) return;
    if(parameters == kCCDHRFC2409Group2) return;
    if(parameters == kCCDHRFC3526Group5) return;

    CCDHParmSet CCDHParm = (CCDHParmSet) parameters;
    if(CCDHParm->malloced) {
        free((ccdh_gp_t)parameters->gp); //const is discarded in retval->gp
    }
    CCDHParm->malloced = 0;
    CCDHParm->gp = NULL;
    free(CCDHParm);
}

// TODO - needs PKCS3 in/out
CCDHParameters
CCDHParametersCreateFromPKCS3(const void *data, size_t __unused len)
{
    CC_DEBUG_LOG("Entering\n");
    CC_NONULLPARMRETNULL(data);
    return NULL;
}

size_t
CCDHParametersPKCS3EncodeLength(CCDHParameters __unused parms)
{
    CC_DEBUG_LOG("Entering\n");
    return 0;
}

size_t
CCDHParametersPKCS3Encode(CCDHParameters __unused parms, void * __unused data, size_t __unused dataAvailable)
{
    CC_DEBUG_LOG("Entering\n");
    return 0;
}

