// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SGX_QUOTE
#define _SGX_QUOTE

#include <openenclave/bits/evidence.h>
#include <openenclave/host.h>

#include "../../../../host/sgx/platformquoteprovider.h"

void log(const char* fmt, ...);
void secure_verify_quote_provider_log(
    sgx_ql_log_level_t level,
    const char* message);
void set_log_callback();

oe_result_t verify_oe_evidence(
    oe_enclave_t* enclave,
    const oe_uuid_t* foramt_id,
    const char* evidence_filename);

oe_result_t verify_oe_certificate(
    oe_enclave_t* enclave,
    const char* certificate_filename);

#endif // _SGX_QUOTE
