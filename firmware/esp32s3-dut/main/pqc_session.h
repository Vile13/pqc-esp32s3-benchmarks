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
    int64_t encap_us;      /* encapsulation to the pinned static key */
    int64_t eph_encap_us;  /* encapsulation to the ephemeral key, mode B only */
    bool forward_secrecy;
    size_t handshake_bytes;
} pqc_session_t;

/* Mode A: pinned static server key, no forward secrecy.
 * Mode B: additional ephemeral ML-KEM key pair per session. */
typedef enum
{
    PQC_MODE_A = 0,
    PQC_MODE_B_FORWARD_SECRECY = 1,
} pqc_mode_t;

/* Connect to the configured server, run the PQC-IoT-1 handshake in the given
 * mode and send `record_count` encrypted records. Wi-Fi must already be up. */
bool pqc_session_run(pqc_mode_t mode, int record_count);

#endif /* PQC_SESSION_H */
