#include <openssl/crypto.h>
#include <kyber/symmetric.h>
#include "tempo_internal.h"

void tempo_fls(polyvec *v, const uint8_t *seed)
{
    xof_state state;
    uint8_t buf[5 * XOF_BLOCKBYTES];
    for (uint8_t x = 0; x < KYBER_K; x++)
    {
        xof_absorb(&state, seed, x, 0);
        xof_squeezeblocks(buf, 5, &state);
        int ctr = 0;
        for (int i = 0, buf_i = 0; i <= 279; i++, buf_i += 3)
        {
            uint16_t d[2];
            int d_ok[2];
            d[0] = ((buf[buf_i + 0] >> 0) |
                    ((uint16_t)buf[buf_i + 1] << 8)) &
                   0xFFF;
            d[1] = ((buf[buf_i + 1] >> 4) |
                    ((uint16_t)buf[buf_i + 2] << 4)) &
                   0xFFF;
            d_ok[0] = (d[0] < KYBER_Q);
            d_ok[1] = (d[1] < KYBER_Q);
            for (int d_i = 0; d_i < 2; d_i++)
            {
                int flag = 0;
                for (int j = 0; j < KYBER_N; j++)
                {
                    int match = (j == ctr);
                    int mask = match * d_ok[d_i];
                    int16_t *coeffs = v->vec[x].coeffs;
                    coeffs[j] = coeffs[j] * (1 - mask) + d[d_i] * mask;
                    flag += mask;
                }
                ctr += flag;
            }
        }
    }
    OPENSSL_cleanse(&state, sizeof(xof_state));
    OPENSSL_cleanse(buf, 5 * XOF_BLOCKBYTES);
}
