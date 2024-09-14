#include <stdio.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/rand.h>

#define MESSAGE_ARRAY_SIZE 3                                                               /**< Number of plaintext messages to be encrypted. */
#define MAXIMUM_TITLE_STRING 64                                                            /**< Maximum number of characters allowed in a title string. */
#define AES_KEY_SIZE_AS_BYTES 32                                                           /**< AES key size in bytes (256 bits for AES-256). */
#define AES_KEY_SIZE_AS_BITS (AES_KEY_SIZE_AS_BYTES * 8)                                   /**< AES key size in bits, calculated as bytes * 8. */
#define AES_BLOCK_SIZE 16                                                                  /**< AES block size in bytes (128 bits for AES). */
#define AES_IV_SIZE 16                                                                     /**< AES initialization vector (IV) size in bytes, matching the AES block size. */
#define AES_MAX_PADDING_SIZE 16                                                            /**< Maximum padding size in bytes (same as AES block size, for PKCS#7 padding). */
#define MAX_PLAIN_TEXT_SIZE 128                                                            /**< Maximum size for each plaintext message buffer in bytes. */
#define CIPHER_TEXT_SIZE (MAX_PLAIN_TEXT_SIZE * MESSAGE_ARRAY_SIZE + AES_MAX_PADDING_SIZE) /**< Total size for ciphertext, accounting for message array and padding. */
#define DECRYPTED_TEXT_SIZE CIPHER_TEXT_SIZE                                               /**< Decrypted text size, same as ciphertext size, to accommodate padding. */
#define LAST_INDEX(size) ((size) - 1)                                                      /**< Returns the last valid index of an array based on its size. */

/**< Encryption Key */
const uint8_t key_au8[AES_KEY_SIZE_AS_BYTES] = {0xF0, 0xA7, 0x4C, 0x58, 0x56, 0xC1, 0x37, 0xBB, 0xEF, 0x0F, 0x3D, 0xBC, 0x6C, 0x6D, 0x71, 0x0B, 0x18, 0x2B, 0xCC, 0x4A, 0x7E, 0x92, 0x37, 0xE4, 0xE0, 0x96, 0xC7, 0x47, 0x7D, 0x58, 0xEA, 0xD8};

void print_data(const char *title_pu8, const uint8_t *data_pu8, const uint32_t len_u32);

int main()
{
    printf("Program Start\r\n");

    /**< Initial variables for the encryption process */
    EVP_CIPHER_CTX *ctx_pstruct = NULL;                                   /**< Pointer to encryption context structure for the EVP API. */
    AES_KEY encryptKey_struct = {0};                                      /**< AES encryption key structure used during the encryption process. */
    uint8_t iv_au8[AES_IV_SIZE] = {0};                                    /**< Initialization vector (IV) for AES encryption, ensures unique ciphertext for identical plaintext. */
    int32_t stringLength_s32[MESSAGE_ARRAY_SIZE] = {0};                   /**< Array holding the length of each plaintext message to be encrypted. */
    uint8_t plainText_au8[MESSAGE_ARRAY_SIZE][MAX_PLAIN_TEXT_SIZE] = {0}; /**< Buffer holding plaintext messages for encryption. */
    uint8_t cipherText_au8[CIPHER_TEXT_SIZE] = {0};                       /**< Buffer to store the resulting ciphertext after encryption, initialized to zero. */
    int32_t ciphertextTotalLength_s32 = 0;                                /**< Total length of the ciphertext after encryption. */

    /**< Initial variables for the decryption process */
    AES_KEY decryptKey_struct = {0};                      /**< AES decryption key structure used during the decryption process. */
    uint8_t originalIV_au8[AES_BLOCK_SIZE] = {0};         /**< Copy of the original IV, reused during decryption. */
    uint8_t decryptedText_au8[DECRYPTED_TEXT_SIZE] = {0}; /**< Buffer to store the decrypted text, initialized to zero. */
    int32_t decryptedTotalLength_s32 = 0;                  /**< Total length of the decrypted text after decryption. */

    /**< ********************* Encryption Process  **********************/
    /**< Generate IV 16 byte for AES256-CBC */
    if (!RAND_bytes(iv_au8, sizeof(iv_au8)))
    {
        printf("Error generating IV\r\n");
    }
    else
    {
        /**< Print key and IV value */
        print_data("Key", key_au8, sizeof(key_au8));
        print_data("IV", iv_au8, sizeof(iv_au8));

        /**< Simulate message that need to encrypt testing */
        for (uint16_t i_u16 = 0; i_u16 < MESSAGE_ARRAY_SIZE; i_u16++)
        {
            stringLength_s32[i_u16] = snprintf(&plainText_au8[i_u16][0], MAX_PLAIN_TEXT_SIZE, "This is a test of AES encryption:%d;\r\n", i_u16);
            printf("plaintext[%d]:%.*s\r\n", i_u16, stringLength_s32[i_u16], &plainText_au8[i_u16][0]);
            print_data("plaintext as hex", &plainText_au8[i_u16][0], stringLength_s32[i_u16]);
        }

        /**< Insert IV data to cipherText_au8 buffer */
        memcpy(&cipherText_au8[0], iv_au8, AES_IV_SIZE);

        /**< Initialize the encryption context on the stack */
        ctx_pstruct = EVP_CIPHER_CTX_new();

        if (NULL == ctx_pstruct)
        {
            printf("Error creating EVP_CIPHER_CTX\r\n");
        }
        else
        {
            if (1 != EVP_EncryptInit_ex(ctx_pstruct, EVP_aes_256_cbc(), NULL, key_au8, iv_au8))
            {
                printf("Error initializing encryption\r\n");
            }
            else
            {
                int32_t encryptStatus_s32 = 0;
                ciphertextTotalLength_s32 = 0;
                for (uint16_t i_u16 = 0; i_u16 < MESSAGE_ARRAY_SIZE; i_u16++)
                {
                    int32_t cipherLength_s32 = 0;
                    /**<  Encrypt the data */
                    encryptStatus_s32 = EVP_EncryptUpdate(ctx_pstruct, (unsigned char *)&cipherText_au8[AES_IV_SIZE + ciphertextTotalLength_s32], &cipherLength_s32, &plainText_au8[i_u16][0], stringLength_s32[i_u16]);
                    if (1 != encryptStatus_s32)
                    {
                        printf("Error during encryption, status:%d, index:%d\r\n", encryptStatus_s32, i_u16);
                        break;
                    }
                    else
                    {
                        ciphertextTotalLength_s32 += cipherLength_s32;
                        printf("Round[%d],ciphertextTotalLength_s32:%d, lengthRound2_s32:%d\r\n", i_u16, ciphertextTotalLength_s32, cipherLength_s32);
                        printf("Encrypt round:%d success\r\n", i_u16);
                    }
                }

                if (1 != encryptStatus_s32)
                {
                    printf("AES encryption stop\r\n");
                }
                else
                {
                    /**<  Finalize encryption */
                    int32_t lengthFinal_s32 = 0;
                    if (1 != EVP_EncryptFinal_ex(ctx_pstruct, (unsigned char *)&cipherText_au8[AES_IV_SIZE + ciphertextTotalLength_s32], &lengthFinal_s32))
                    {
                        printf("Error during final encryption step\n");
                    }
                    ciphertextTotalLength_s32 += lengthFinal_s32;
                    printf("ciphertextTotalLength_s32 final:%d\r\n", ciphertextTotalLength_s32);
                    print_data("iv and ciphertext", cipherText_au8, AES_IV_SIZE + ciphertextTotalLength_s32);
                }
            }
            EVP_CIPHER_CTX_free(ctx_pstruct);
            ctx_pstruct = NULL;
        }
    }

    /**< ********************* Decryption Process  **********************/
    /**< Initialize decryption operation */
    /**< Initialize the encryption context on the stack */
    if (NULL == ctx_pstruct)
    {
        ctx_pstruct = EVP_CIPHER_CTX_new();
    }

    if (NULL == ctx_pstruct)
    {
        printf("Error creating EVP_CIPHER_CTX\r\n");
    }
    else
    {
        if (1 != EVP_DecryptInit_ex(ctx_pstruct, EVP_aes_256_cbc(), NULL, key_au8, &cipherText_au8[0]))
        {
            printf("Error initializing decryption\n");
        }
        else
        {
            /**< Decrypt the data */
            int32_t maxChunkSize_s32 = 32;
            int32_t chipherCurrentIndex_s32 = 0;
            int32_t decryptedLength_s32 = 0;
        
            decryptedTotalLength_s32 = 0;


            while(chipherCurrentIndex_s32 < ciphertextTotalLength_s32)
            {
                int32_t chunkSize_s32 = 0;
                if((ciphertextTotalLength_s32 - chipherCurrentIndex_s32) > maxChunkSize_s32)
                {
                    chunkSize_s32 = maxChunkSize_s32;
                }
                else
                {
                    chunkSize_s32 = ciphertextTotalLength_s32 - chipherCurrentIndex_s32;
                }
                
                if (1 != EVP_DecryptUpdate(ctx_pstruct, &decryptedText_au8[decryptedTotalLength_s32], &decryptedLength_s32, &cipherText_au8[AES_IV_SIZE+chipherCurrentIndex_s32], chunkSize_s32))
                {
                    printf("Error during decryption\n");
                    break;
                }
                else
                {
                    chipherCurrentIndex_s32 += chunkSize_s32;
                    decryptedTotalLength_s32 += decryptedLength_s32; 
                    printf("current index:%d, decryptedLength_s32:%d, decryptedTotalLength_s32:%d\r\n", chipherCurrentIndex_s32, decryptedLength_s32, decryptedTotalLength_s32);
                }
            }
            
            /**< Finalize decryption */
            if (1 != EVP_DecryptFinal_ex(ctx_pstruct, &decryptedText_au8[decryptedTotalLength_s32], &decryptedLength_s32))
            {
                printf("Error during final decryption step\r\n");
            }
            printf("length_s32:%d\r\n", decryptedLength_s32);
            decryptedTotalLength_s32 += decryptedLength_s32;
            print_data("Decrypted text", decryptedText_au8, decryptedTotalLength_s32);
            decryptedText_au8[decryptedTotalLength_s32] = '\0'; // Null-terminate the decrypted string
            printf("Decrypted message:\r\n%s\r\n", decryptedText_au8);
    
        }
        EVP_CIPHER_CTX_free(ctx_pstruct);
        ctx_pstruct = NULL;
    }

    return 0;
}

/**
 * @brief Print data in a hexadecimal format with a title.
 *
 * This function prints the data in a formatted hexadecimal string, prefixed by a title.
 * It first checks if the title or data pointer is NULL and prints an error message if so.
 * Otherwise, it prints the title followed by the hex representation of the data.
 *
 * @param[in] title_pu8   Pointer to the string title to print.
 * @param[in] data_pu8    Pointer to the data buffer to be printed in hexadecimal format.
 * @param[in] len_u32     The length of the data to be printed.
 *
 * @return None.
 *
 * @note This function assumes `MAXIMUM_TITLE_STRING` is defined elsewhere.
 */
void print_data(const char *title_pu8, const uint8_t *data_pu8, const uint32_t len_u32)
{
    if (NULL == title_pu8 || NULL == data_pu8)
    {
        printf("Parameter is null, title: 0x%" PRIXPTR ", data: 0x%" PRIXPTR "\n", (uintptr_t)title_pu8, (uintptr_t)data_pu8);
    }
    else
    {
        printf("%.*s = {\r\n\t", MAXIMUM_TITLE_STRING, title_pu8);
        for (uint32_t i_u32 = 0; i_u32 < len_u32; i_u32++)
        {
            if ((i_u32 > 0) && (0 == i_u32 % 16))
            {
                printf("\r\n\t");
            }
            printf("0x%02X", data_pu8[i_u32]);
            if (i_u32 < LAST_INDEX(len_u32))
            {
                printf(",");
            }
        }
        printf("\r\n};\r\n\r\n");
    }
}
