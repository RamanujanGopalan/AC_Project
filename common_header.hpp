void aes_cpu_encrypt(uint8_t *input,uint8_t *output, uint8_t *keys,size_t blocks);
void aes_cpu_encrypt_ctr(uint8_t *output, uint8_t *roundKeys, size_t blocks, uint64_t ctr);
uint8_t* aes_cpu_get_key();

void des_cpu_encrypt(uint8_t *input, uint8_t *output, uint64_t key, size_t blocks);
void des_cpu_encrypt_ctr(uint8_t *output, uint64_t key, size_t blocks, uint64_t ctr);
uint64_t des_cpu_get_key();

void kalyna_cpu_encrypt(uint8_t *in, uint8_t *out, uint8_t *keys, size_t blocks);
void kalyna_cpu_encrypt_ctr(uint8_t *out, uint8_t *keys, size_t blocks, uint64_t ctr);
uint8_t* kalyna_cpu_get_key();

void simon_cpu_encrypt(uint8_t *input, uint8_t *output, uint64_t* keys, size_t blocks);
void simon_cpu_encrypt_ctr(uint8_t *output, uint64_t *keys, size_t blocks, uint64_t ctr);
uint64_t* simon_cpu_get_key();

void gift_cpu_encrypt(uint8_t *h_plain, uint8_t *h_cipher, uint8_t *round_keys,size_t blocks);

uint8_t* gift_cpu_get_key();