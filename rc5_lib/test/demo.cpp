#include <stdio.h>
#include <time.h>


#include "rc5.h"


int main()
{ 
  RC5Simple rc5(true);

  printf("RC5-32/12/16 examples\n");

  printf("Library version: %s\n", rc5.RC5_GetVersion() );

  // ------------------------------------
  // Byte array encrypt / decrypt example
  // ------------------------------------

  printf("\nByte array encrypt example\n\n");

  #define DATA_SIZE 100

  // Generate first data
  unsigned char data[DATA_SIZE];

  printf("Plain byte array:\n");
  for(int i=0; i<DATA_SIZE; i++)
   {
    data[i]=(unsigned char)(i+'0');
    printf("%.2X ", data[i]);
   }
  printf("\n");


  // Generate key (in real, generate from password)
  unsigned char key[RC5_B];
  for(int i=0; i<RC5_B; i++)
    key[i]=i*2;


  // -------------
  // Array encrypt
  // -------------

  // Convert key to vector
  vector<unsigned char> v_key(RC5_B);
  for(int i=0; i<RC5_B; i++)
   v_key[i]=key[i];

  printf("\nKey for encrypt:\n");
  for(int i=0; i<RC5_B; i++)
   printf("%.2X ", v_key[i]);
  printf("\n");


  // Convert data array to vector
  vector<unsigned char> v_data(DATA_SIZE);
  for(int i=0; i<DATA_SIZE; i++)
   v_data[i]=data[i];
 
  // Result vector for crypt data
  vector<unsigned char> v_crypt_data;


  // Example for force set format version
  // rc5.RC5_SetFormatVersionForce(RC5_FORMAT_VERSION_1);

  // Encrypt
  rc5.RC5_SetKey(v_key);
  rc5.RC5_Encrypt(v_data, v_crypt_data);

  printf("\nEncrypt byte array:\n");
  for(int i=0; i<v_crypt_data.size(); i++)
   printf("%.2X ", v_crypt_data[i]);
  printf("\n");


  // -------------
  // Array decrypt
  // -------------

  // Clear result vector for decrypt data
  v_data.clear();

  // Decrypt
  rc5.RC5_SetKey(v_key);
  rc5.RC5_Decrypt(v_crypt_data, v_data);

  printf("\nDecrypt byte array:\n");
  for(int i=0; i<v_data.size(); i++)
   printf("%.2X ", v_data[i]);
  printf("\n");


  // ------------------------------
  // File encrypt / decrypt example
  // ------------------------------

//   printf("\nEncrypt/decrypt file example: example.txt -> example.txt.encrypt -> example.txt.decrypt\n");

//   rc5.RC5_SetKey(v_key);

//   rc5.RC5_EncryptFile("example.txt", "example.txt.encrypt");

//   rc5.RC5_DecryptFile("example.txt.encrypt", "example.txt.decrypt");

  return 0;
}