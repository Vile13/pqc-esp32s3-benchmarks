#ifndef PQC_SESSION_H
#define PQC_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint8_t session_id[8];
    uint8_t c2s[32];
    uint64_t send_seq;
    int64_t encap_us;
    size_t handshake_bytes;
} pqc_session_t;

/* Connect to the configured server, run the PQC-IoT-1 mode A handshake and send
 * `record_count` encrypted records. Wi-Fi must already be up. */
bool pqc_session_run(int record_count);

#endif /* PQC_SESSION_H */
