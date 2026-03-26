void aes_cpu_encrypt(uint8_t *input,uint8_t *output, uint8_t *keys,int blocks);
uint8_t* aes_cpu_get_key();

void des_cpu_encrypt(uint8_t *input, uint8_t *output, uint64_t key, int blocks);
uint64_t des_cpu_get_key();

void kalyna_cpu_encrypt(uint8_t *in, uint8_t *out, uint8_t *keys, int blocks);
uint8_t* kalyna_cpu_get_key();

void simon_cpu_encrypt(uint8_t *input, uint8_t *output, uint64_t* keys, int blocks);
uint64_t* simon_cpu_get_key();