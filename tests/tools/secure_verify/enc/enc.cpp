// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secure_verify_t.h"

// This is the identity validation callback. A TLS connecting party (client or
// server) can verify the passed in identity information to decide whether to
// accept a connection request
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    OE_TRACE_INFO("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    if (identity->security_version < 1)
    {
        OE_TRACE_ERROR(
            "identity->security_version checking failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves. In a real scenario,
    // custom id checking should be done here
    OE_TRACE_INFO("identity->unique_id :");
    oe_hex_dump(identity->unique_id, OE_COUNTOF(identity->unique_id));

    OE_TRACE_INFO("identity->signer_id :");
    oe_hex_dump(identity->signer_id, OE_COUNTOF(identity->signer_id));

    OE_TRACE_INFO("identity->product_id :");
    oe_hex_dump(identity->product_id, OE_COUNTOF(identity->product_id));

    result = OE_OK;
done:
    return result;
}

oe_result_t verify_plugin_evidence(
    const oe_uuid_t* format_id,
    uint8_t* evidence,
    size_t evidence_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    OE_CHECK(oe_verifier_initialize());

    OE_CHECK_MSG(
        oe_verify_evidence(
            format_id,
            evidence,
            evidence_size,
            nullptr,
            0,
            NULL,
            0,
            &claims,
            &claims_length),
        "Failed to verify evidence. result=%u (%s)\n",
        result,
        oe_result_str(result));

    result = OE_OK;

done:
    OE_CHECK(oe_free_claims(claims, claims_length));
    OE_CHECK(oe_verifier_shutdown());

    return result;
}

oe_result_t verify_plugin_certificate(
    uint8_t* certificate,
    size_t certificate_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    OE_CHECK_MSG(
        oe_verify_attestation_certificate(
            certificate, certificate_size, enclave_identity_verifier, nullptr),
        "Failed to verify the certificate. result=%u (%s)\n",
        result,
        oe_result_str(result));

    result = OE_OK;

done:
    OE_CHECK(oe_free_claims(claims, claims_length));
    OE_CHECK(oe_verifier_shutdown());

    return result;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
