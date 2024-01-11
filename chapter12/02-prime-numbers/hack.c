/*
 * Malware Development for Ethical Hackers
 * hack.c - using prime numbers and modular arithmetic. 
 * C/C++ implementation
 * author: @cocomelonc
*/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to check if a number is prime
int is_prime(int n) {
  if (n <= 1) {
    return 0;
  }
  for (int i = 2; i <= sqrt(n); i++) {
    if (n % i == 0) {
      return 0;
    }
  }
  return 1;
}

// Function to find the greatest common divisor (GCD) of two numbers
int gcd(int a, int b) {
  while (b != 0) {
    int temp = b;
    b = a % b;
    a = temp;
  }
  return a;
}

// Function to find a number e such that 1 < e < phi and gcd(e, phi) = 1
int find_public_exponent(int phi) {
  int e = 2;
  while (e < phi) {
    if (gcd(e, phi) == 1) {
      return e;
    }
    e++;
  }
  return -1; // Error: Unable to find public exponent
}

// Function to find the modular multiplicative inverse of a number
int mod_inverse(int a, int m) {
  for (int x = 1; x < m; x++) {
    if ((a * x) % m == 1) {
      return x;
    }
  }
  return -1; // Error: Modular inverse does not exist
}

// Function to perform modular exponentiation
int mod_pow(int base, int exp, int mod) {
  int result = 1;
  while (exp > 0) {
    if (exp % 2 == 1) {
      result = (result * base) % mod;
    }
    base = (base * base) % mod;
    exp /= 2;
  }
  return result;
}

int main() {
  // Step 1: Choose two large prime numbers
  int p = 61;
  int q = 53;

  // Step 2: Compute n (modulus) and phi (Euler's totient function)
  int n = p * q;
  int phi = (p - 1) * (q - 1);

  // Step 3: Choose a public exponent e
  int e = find_public_exponent(phi);

  if (e == -1) {
    printf("Error: Unable to find public exponent.\n");
    return 1;
  }

  // Step 4: Compute the private exponent d
  int d = mod_inverse(e, phi);

  if (d == -1) {
    printf("Error: Unable to compute private exponent.\n");
    return 1;
  }

  // Display public and private keys
  printf("Public Key (n, e): (%d, %d)\n", n, e);
  printf("Private Key (n, d): (%d, %d)\n", n, d);

  // Step 5: Encrypt a message using the public key
  int plaintext = 42;
  int ciphertext = mod_pow(plaintext, e, n);
  printf("Encrypted Message: %d\n", ciphertext);

  // Step 6: Decrypt the message using the private key
  int decrypted_message = mod_pow(ciphertext, d, n);
  printf("Decrypted Message: %d\n", decrypted_message);

  return 0;
}
