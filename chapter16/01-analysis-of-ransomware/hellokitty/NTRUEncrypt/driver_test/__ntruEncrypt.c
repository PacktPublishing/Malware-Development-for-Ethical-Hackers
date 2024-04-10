
#ifndef __KERNEL__
#  define __KERNEL__
#endif
#ifndef MODULE
#  define MODULE
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include "ntru_crypto.h"

/* entropy function
 *
 * THIS IS AN EXAMPLE FOR WORKING SAMPLE CODE ONLY.
 * IT DOES NOT SUPPLY REAL ENTROPY BECAUSE THE RANDOM SEED IS FIXED.
 *
 * IT SHOULD BE CHANGED SO THAT EACH COMMAND THAT REQUESTS A BYTE
 * OF ENTROPY RECEIVES A RANDOM BYTE.
 *
 * Returns 1 for success, 0 for failure.
 */

static uint8_t
get_entropy(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{
    /* 21 bytes of entropy are needed to instantiate a DRBG with a
     * security strength of 112 bits.
     */
    static uint8_t seed[] = {
        'U','s','e',' ','a',' ','d','i','f','f','e','r','e','n','t',' ',
        's','e','e','d','!'
    };
    static size_t index;

    if (cmd == INIT) {
        /* Any initialization for a real entropy source goes here. */
        index = 0;
        return 1;
    }

    if (out == NULL)
        return 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        /* Here we return the number of bytes needed from the entropy
         * source to obtain 8 bits of entropy.  Maximum is 8.
         */
        *out = 1;                       /* this is a perfectly random source */
        return 1;
    }

    if (cmd == GET_BYTE_OF_ENTROPY) {
        if (index == sizeof(seed))
            return 0;                   /* used up all our entropy */

        *out = seed[index++];           /* deliver an entropy byte */
        return 1;
    }
    return 0;
}


/* Personalization string to be used for DRBG instantiation.
 * This is optional.
 */
static uint8_t const pers_str[] = {
    'S', 'S', 'L', ' ', 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n'
};


/* AES-128 key to be encrypted. */
static uint8_t const aes_key[] = {
    0xf3, 0xe9, 0x87, 0xbb, 0x18, 0x08, 0x3c, 0xaa,
    0x7b, 0x12, 0x49, 0x88, 0xaf, 0xb3, 0x22, 0xd8
};


static void __exit ntru_exit_module(void)
{
    printk(KERN_DEBUG "Shutting down NTRUEncrypt Sample\n");
}

/* 
 *
 * This sample code will:
 *   1) generate a public-key pair for the EES401EP2 parameter set
 *   2) DER-encode the public key for storage in a certificate
 *   3) DER-decode the public key from a certificate for use
 *   4) encrypt a 128-bit AES key
 *   5) decrypt the 128-bit AES key
 */
static int __init ntru_init_module(void)
{
    uint8_t public_key[557];          /* sized for EES401EP2 */
    uint16_t public_key_len;          /* no. of octets in public key */
    uint8_t private_key[607];         /* sized for EES401EP2 */
    uint16_t private_key_len;         /* no. of octets in private key */
    uint8_t encoded_public_key[591];  /* sized for EES401EP2 */
    uint16_t encoded_public_key_len;  /* no. of octets in encoded public key */
    uint8_t ciphertext[552];          /* sized fof EES401EP2 */
    uint16_t ciphertext_len;          /* no. of octets in ciphertext */
    uint8_t plaintext[16];            /* size of AES-128 key */
    uint16_t plaintext_len;           /* no. of octets in plaintext */
    uint8_t *next = NULL;             /* points to next cert field to parse */
    DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
    uint32_t rc;                      /* return code */
    bool error = FALSE;               /* records if error occurred */

    /* Instantiate a DRBG with 112-bit security strength for key generation
     * to match the security strength of the EES401EP2 parameter set.
     * Here we've chosen to use the personalization string.
     */
    rc = ntru_crypto_drbg_instantiate(112, pers_str, sizeof(pers_str),
                                      (ENTROPY_FN) &get_entropy, &drbg);
    if (rc != DRBG_OK)
        /* An error occurred during DRBG instantiation. */
        return 1;

    printk(KERN_DEBUG "DRBG at 112-bit security for key generation instantiated successfully.\n");


    /* Let's find out how large a buffer we need for the public and private
     * keys.
     */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &public_key_len,
                                         NULL, &private_key_len, NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer sizes needed. */
        return 1;
    printk(KERN_DEBUG "Public-key buffer size required: %d octets.\n", public_key_len);
    printk(KERN_DEBUG "Private-key buffer size required: %d octets.\n", private_key_len);


    /* Now we could allocate a buffer of length public_key_len to hold the
     * public key, and a buffer of length private_key_len to hold the private
     * key, but in this example we already have them as local variables.
     */


    /* Generate a key pair for EES401EP2.
     * We must set the public-key length to the size of the buffer we have
     * for the public key, and similarly for the private-key length.
     * We've already done this by getting the sizes from the previous call
     * to ntru_crypto_ntru_encrypt_keygen() above.
     */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &public_key_len,
                                         public_key, &private_key_len,
                                         private_key);
    if (rc != NTRU_OK)
        /* An error occurred during key generation. */
        error = TRUE;
    printk(KERN_DEBUG "Key-pair for NTRU_EES401EP2 generated successfully.\n");


    /* Uninstantiate the DRBG. */
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    if ((rc != DRBG_OK) || error)
        /* An error occurred uninstantiating the DRBG, or generating keys. */
        return 1;
    printk(KERN_DEBUG "Key-generation DRBG uninstantiated successfully.\n");


    /* Let's find out how large a buffer we need for holding a DER-encoding
     * of the public key.
     */
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len, NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer size needed. */
        return 1;
    printk(KERN_DEBUG "DER-encoded public-key buffer size required: %d octets.\n",
            encoded_public_key_len);


    /* Now we could allocate a buffer of length encoded_public_key_len to
     * hold the encoded public key, but in this example we already have it
     * as a local variable.
     */


    /* DER-encode the public key for inclusion in a certificate.
     * This creates a SubjectPublicKeyInfo field from a public key.
     * We must set the encoded public-key length to the size of the buffer
     * we have for the encoded public key.
     * We've already done this by getting the size from the previous call
     * to ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKey() above.
     */
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len,
            encoded_public_key);
    printk(KERN_DEBUG "Public key DER-encoded for SubjectPublicKeyInfo successfully.\n");


    /* Now suppose we are parsing a certificate so we can use the
     * public key it contains, and the next field is the SubjectPublicKeyInfo
     * field.  This is indicated by the "next" pointer.  We'll decode this
     * field to retrieve the public key so we can use it for encryption.
     * First let's find out how large a buffer we need for holding the
     * DER-decoded public key.
     */
    next = encoded_public_key;          /* the next pointer will be pointing
                                           to the SubjectPublicKeyInfo field */
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key_len, NULL, &next);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer size needed. */
        return 1;
    printk(KERN_DEBUG "Public-key buffer size required: %d octets.\n", public_key_len);


    /* Now we could allocate a buffer of length public_key_len to hold the
     * decoded public key, but in this example we already have it as a
     * local variable.
     */


    /* Decode the SubjectPublicKeyInfo field.  Note that if successful,
     * the "next" pointer will now point to the next field following
     * the SubjectPublicKeyInfo field.
     */
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key_len, public_key, &next);
    if (rc != NTRU_OK)
        /* An error occurred decoding the SubjectPublicKeyInfo field.
         * This could indicate that the field is not a valid encoding
         * of an NTRUEncrypt public key.
         */
        return 1;
    printk(KERN_DEBUG "Public key decoded from SubjectPublicKeyInfo successfully.\n");


    /* We need to instantiate a DRBG with 112-bit security strength for
     * encryption to match the security strength of the EES401EP2 parameter
     * set that we generated keys for.
     * Here we've chosen not to use the personalization string.
     */
    rc = ntru_crypto_drbg_instantiate(112, NULL, 0, (ENTROPY_FN) &get_entropy,
                                      &drbg);
    if (rc != DRBG_OK)
        /* An error occurred during DRBG instantiation. */
        return 1;
    printk(KERN_DEBUG "DRBG at 112-bit security for encryption instantiated "
            "successfully.\n");


    /* Now that we have the public key from the certificate, we'll use
     * it to encrypt an AES-128 key.
     * First let's find out how large a buffer we need for holding the
     * ciphertext.
     */
    rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                  sizeof(aes_key), aes_key, &ciphertext_len,
                                  NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer size needed. */
        return 1;
    printk(KERN_DEBUG "Ciphertext buffer size required: %d octets.\n", ciphertext_len);


    /* Now we could allocate a buffer of length ciphertext_len to hold the
     * ciphertext, but in this example we already have it as a local variable.
     */


    /* Encrypt the AES-128 key.
     * We must set the ciphertext length to the size of the buffer we have
     * for the ciphertext.
     * We've already done this by getting the size from the previous call
     * to ntru_crypto_ntru_encrypt() above.
     */
     rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                                   sizeof(aes_key), aes_key, &ciphertext_len,
                                   ciphertext);
     if (rc != NTRU_OK)
         /* An error occurred encrypting the AES-128 key. */
         error = TRUE;
     printk(KERN_DEBUG "AES-128 key encrypted successfully.\n");


    /* Uninstantiate the DRBG. */
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    if ((rc != DRBG_OK) || error)
        /* An error occurred uninstantiating the DRBG, or encrypting. */
        return 1;
    printk(KERN_DEBUG "Encryption DRBG uninstantiated successfully.\n");


     /* We've received ciphertext, and want to decrypt it.
      * We can find out the maximum plaintext size as follows.
      */
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key, ciphertext_len,
                                  ciphertext, &plaintext_len, NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer size needed. */
        return 1;
    printk(KERN_DEBUG "Maximum plaintext buffer size required: %d octets.\n",
            plaintext_len);

    /* Now we could allocate a buffer of length plaintext_len to hold the
     * plaintext, but note that plaintext_len has the maximum plaintext
     * size for the EES401EP2 parameter set.  Since we know that we've
     * received an encrypted AES-128 key in this example, and since we
     * already have a plaintext buffer as a local variable, we'll just
     * supply the length of that plaintext buffer for decryption.
     */
    plaintext_len = sizeof(plaintext);
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key, ciphertext_len,
                                  ciphertext, &plaintext_len, plaintext);
    if (rc != NTRU_OK)
        /* An error occurred decrypting the AES-128 key. */
        return 1;
    printk(KERN_DEBUG "AES-128 key decrypted successfully.\n");
    
    /* And now the plaintext buffer holds the decrypted AES-128 key. */
    printk(KERN_DEBUG "Sample code completed successfully.\n");

    return 0;
}

module_init(ntru_init_module);
module_exit(ntru_exit_module);
MODULE_AUTHOR("Pete Jenney");
MODULE_LICENSE("GPL");
