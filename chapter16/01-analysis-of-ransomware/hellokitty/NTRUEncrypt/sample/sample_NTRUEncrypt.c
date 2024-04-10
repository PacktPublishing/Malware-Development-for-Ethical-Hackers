/******************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information. 
 *
 *
 *********************************************************************************/
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    /* 2k/8 bytes of entropy are needed to instantiate a DRBG with a
     * security strength of k bits. Here k = 112.
     */
    static uint8_t seed[28] = {
        'P','l','e','a','s','e',' ','u','s','e',' ','a',' ',
        'd','i','f','f','e','r','e','n','t',' ','s','e','e','d','!'
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


/* Dumps a buffer in hex to the screen for debugging */
void
DumpHex(
    const unsigned char* buf,
    int len)
{
    int i;
    for(i=0;i<len;i++)
    {
      if(i&0x1f) printf(":");
      printf("%02X",buf[i]);
      if((i&0x1f)==0x1f) printf("\n");
    }
    printf("\n");
}


/* main
 *
 * This sample code will:
 *   1) generate a public-key pair for the EES401EP2 parameter set
 *   2) DER-encode the public key for storage in a certificate
 *   3) DER-decode the public key from a certificate for use
 *   4) encrypt a 128-bit AES key
 *   5) decrypt the 128-bit AES key
 */
int
main(void)
{
    uint8_t public_key[557];          /* sized for EES401EP2 */
    uint16_t public_key_len;          /* no. of octets in public key */
    uint8_t private_key[607];         /* sized for EES401EP2 */
    uint16_t private_key_len;         /* no. of octets in private key */
    uint16_t expected_private_key_len;
    uint16_t expected_encoded_public_key_len;
    uint8_t encoded_public_key[593];  /* sized for EES401EP2 */
    uint16_t encoded_public_key_len;  /* no. of octets in encoded public key */
    uint8_t ciphertext[552];          /* sized fof EES401EP2 */
    uint16_t ciphertext_len;          /* no. of octets in ciphertext */
    uint8_t plaintext[16];            /* size of AES-128 key */
    uint16_t plaintext_len;           /* no. of octets in plaintext */
    uint8_t *next = NULL;             /* points to next cert field to parse */
    uint32_t next_len;                /* no. of octets it next */
    DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
    uint32_t rc;                      /* return code */
    bool error = FALSE;               /* records if error occurred */
    FILE *Handle=NULL;                /* File Handle for writing NTRU key to file */

    /* Instantiate a DRBG with 112-bit security strength for key generation
     * to match the security strength of the EES401EP2 parameter set.
     * Here we've chosen to use the personalization string.
     */
    rc = ntru_crypto_drbg_instantiate(112, pers_str, sizeof(pers_str),
                                      (ENTROPY_FN) &get_entropy, &drbg);
    if (rc != DRBG_OK)
        /* An error occurred during DRBG instantiation. */
        goto error;
    printf("DRBG at 112-bit security for key generation instantiated "
            "successfully.\n");


    /* Let's find out how large a buffer we need for the public and private
     * keys.
     */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &public_key_len,
                                         NULL, &private_key_len, NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer sizes needed. */
        goto error;
    printf("Public-key buffer size required: %d octets.\n", public_key_len);
    printf("Private-key buffer size required: %d octets.\n", private_key_len);


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
    expected_private_key_len=private_key_len;
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &public_key_len,
                                         public_key, &private_key_len,
                                         private_key);
    if (rc != NTRU_OK)
        /* An error occurred during key generation. */
        error = TRUE;
    if (expected_private_key_len!=private_key_len)
    {
      fprintf(stderr,"private-key-length is different than expected\n");
      error = TRUE;
    }
    printf("Key-pair for NTRU_EES401EP2 generated successfully.\n");


    /* Uninstantiate the DRBG. */
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    if ((rc != DRBG_OK) || error)
        /* An error occurred uninstantiating the DRBG, or generating keys. */
        goto error;
    printf("Key-generation DRBG uninstantiated successfully.\n");


    /* !!! TODO Dump the private key to the screen */
    /* !!! TODO Dump the public key to the screen */
    /* ntru_crypto_ntru_encrypt_key_dump_privkey(params,public_key,private_key,0,NULL); */


    /* Writing both private key and public key to files */  
    Handle=fopen("sample-ntru-key.raw","wb");
    if(Handle!=NULL)
    {
      printf("Writing private key to ntru-key.raw\n");
      fwrite(private_key,private_key_len,1,Handle);
      fclose(Handle);
    }

    Handle=fopen("sample-ntru-pubkey.raw","wb");
    if(Handle!=NULL)
    {
      printf("Writing public key to ntru-pubkey.raw\n");
      fwrite(public_key,public_key_len,1,Handle);
      fclose(Handle);
    }

    /* Let's find out how large a buffer we need for holding a DER-encoding
     * of the public key.
     */
    rc = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
            public_key_len, public_key, &encoded_public_key_len, NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer size needed. */
        goto error;
    printf("DER-encoded public-key buffer size required: %d octets.\n",
            encoded_public_key_len);


    /* Now we could allocate a buffer of length encoded_public_key_len to
     * hold the encoded public key, but in this example we already have it
     * as a local variable.
     */
    expected_encoded_public_key_len=encoded_public_key_len;

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

    if (expected_encoded_public_key_len!=encoded_public_key_len)
    {
      fprintf(stderr,"encoded_public_key_len is different than expected\n");
      error = TRUE;
    }

    printf("Public key DER-encoded for SubjectPublicKeyInfo successfully.\n");

    printf("DER encoded public key in hex:\n");
    DumpHex(encoded_public_key,encoded_public_key_len);

    Handle=fopen("sample-ntru-pubkey.der","wb");
    if(Handle!=NULL)
    {
      printf("Writing DER encoded public key to ntru-pubkey.der\n");
      fwrite(encoded_public_key,encoded_public_key_len,1,Handle);
      fclose(Handle);
    }



    /* Now suppose we are parsing a certificate so we can use the
     * public key it contains, and the next field is the SubjectPublicKeyInfo
     * field.  This is indicated by the "next" pointer.  We'll decode this
     * field to retrieve the public key so we can use it for encryption.
     * First let's find out how large a buffer we need for holding the
     * DER-decoded public key.
     */
    next = encoded_public_key;          /* the next pointer will be pointing
                                           to the SubjectPublicKeyInfo field */
    next_len = encoded_public_key_len;
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key_len, NULL, &next, &next_len);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer size needed. */
        goto error;
    printf("Public-key buffer size required: %d octets.\n", public_key_len);


    /* Now we could allocate a buffer of length public_key_len to hold the
     * decoded public key, but in this example we already have it as a
     * local variable.
     */


    /* Decode the SubjectPublicKeyInfo field.  Note that if successful,
     * the "next" pointer will now point to the next field following
     * the SubjectPublicKeyInfo field, or NULL if we've exhausted the
     * buffer.
     */
    rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(next,
            &public_key_len, public_key, &next, &next_len);
    if (rc != NTRU_OK)
        /* An error occurred decoding the SubjectPublicKeyInfo field.
         * This could indicate that the field is not a valid encoding
         * of an NTRUEncrypt public key.
         */
        goto error;
    printf("Public key decoded from SubjectPublicKeyInfo successfully.\n");


    /* We need to instantiate a DRBG with 112-bit security strength for
     * encryption to match the security strength of the EES401EP2 parameter
     * set that we generated keys for.
     * Here we've chosen not to use the personalization string.
     */
    rc = ntru_crypto_drbg_instantiate(112, NULL, 0, (ENTROPY_FN) &get_entropy,
                                      &drbg);
    if (rc != DRBG_OK)
        /* An error occurred during DRBG instantiation. */
        goto error;
    printf("DRBG at 112-bit security for encryption instantiated "
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
        goto error;
    printf("Ciphertext buffer size required: %d octets.\n", ciphertext_len);


    /* Now we could allocate a buffer of length ciphertext_len to hold the
     * ciphertext, but in this example we already have it as a local variable.
     */


    Handle=fopen("sample-original-plaintext.bin","wb");
    if(Handle!=NULL)
    {
      printf("Writing original plaintext to original-plaintext.bin\n");
      fwrite(aes_key,sizeof(aes_key),1,Handle);
      fclose(Handle);
    }

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
     printf("AES-128 key encrypted successfully.\n");


    Handle=fopen("sample-ciphertext.bin","wb");
    if(Handle!=NULL)
    {
      printf("Writing ciphertext to ciphertext.bin\n");
      fwrite(ciphertext,ciphertext_len,1,Handle);
      fclose(Handle);
    }

    /* Uninstantiate the DRBG. */
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    if ((rc != DRBG_OK) || error)
    {
        fprintf(stderr,"Error: An error occurred uninstantiating the DRBG, or encrypting.\n");
        return 1;
    }
    printf("Encryption DRBG uninstantiated successfully.\n");

    printf("Plaintext:\n");
    DumpHex(aes_key,sizeof(aes_key));

    printf("Ciphertext:\n");
    DumpHex(ciphertext,ciphertext_len);

     /* We've received ciphertext, and want to decrypt it.
      * We can find out the maximum plaintext size as follows.
      */
    rc = ntru_crypto_ntru_decrypt(private_key_len, private_key, ciphertext_len,
                                  ciphertext, &plaintext_len, NULL);
    if (rc != NTRU_OK)
        /* An error occurred requesting the buffer size needed. */
        goto error;
    printf("Maximum plaintext buffer size required: %d octets.\n",
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
    {
        fprintf(stderr,"Error: An error occurred decrypting the AES-128 key.\n");
        return 1;
    }
    printf("AES-128 key decrypted successfully.\n");
    printf("Decoded plaintext length: %d octets\n",plaintext_len);

    if(plaintext_len!=sizeof(aes_key))
    {
        fprintf(stderr,"Error: Decrypted length does not match original plaintext length\n");
        return 1;
    }
    if(memcmp(plaintext,aes_key,sizeof(aes_key)))
    {
        fprintf(stderr,"Error: Decrypted plaintext does not match original plaintext\n");
        return 1;
    }


    Handle=fopen("sample-decoded-plaintext.bin","wb");
    if(Handle!=NULL)
    {
      printf("Writing decoded plaintext to decoded-plaintext.bin\n");
      fwrite(plaintext,plaintext_len,1,Handle);
      fclose(Handle);
    }




    /* And now the plaintext buffer holds the decrypted AES-128 key. */
    printf("Sample code completed successfully.\n");


    return 0;

error:
    printf("Error (0x%x)\n", rc);
    return 1;
}
