//=======================================================
//			       ENCRYPT - DECRYPT RSA
//	Copyright (c) 2020 by Ilias Lamprou & Telis Zacharis
//				    All rights reserved
//========================================================
/* 
	Πριν τρέξετε αυτόν τον κώδικα τοποθετήστε στον ίδιο φάκελλο το δημόσιο 
	το οποίο θα πρέπει να έχει το όνομα private.key 
	
	Με εκτέλεση του αρχείου χωρίς παραμέτρους, αυτό θα προσπαθήσει να 
	διαβάσει το αρχείο private.key
	Για να φορτώσετε αρχεία με άλλο όνομα η σύνταξη είναι:
		teliasED publicKeyName

	O κώδικας αποτελεί το  κομμάτι του αποστολέα 
	Δημιουργεί τα αρχεία rsaOut.txt και aesOut.txt 
	τα οποία θα πρέπει να αποστείλει ο αποστολέας στον παραλήπτη
	
*/


#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <string.h>
#define KEY_LENGTH 8182//768 

//======================================================== loadFile
  unsigned char* readFile(char* filename){
  FILE* f = fopen(filename, "r");
   fseek(f, 0, SEEK_END);
   size_t size = ftell(f);
   printf("\n filesize for read =%d\n",size);
   unsigned char* buf = new unsigned  char[size];
   rewind(f);
   fread(buf, sizeof(char), size, f);
   return buf;
}

//======================================================== printRSA
void printRSA(RSA * rsa, int pri_bub){
	int len=8192;
    BIO *bio = BIO_new(BIO_s_mem());
    if (pri_bub==1) PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    else PEM_write_bio_RSAPublicKey(bio,  rsa);
    size_t  key_len = BIO_pending(bio);
    char* key = (char*)malloc(key_len + 1);
    BIO_read(bio, key, key_len);
    key[key_len] = '\0';
    printf("\n%s\n",  key);
}

//======================================================== sha256
 unsigned char * getHMAC(unsigned char *key,unsigned char *data , int dataSize){
  unsigned char *result;
  int i;
  static char res_hexstring[32];
  //result = HMAC(EVP_sha256(), (unsigned char*) key, strlen((char *)key),(unsigned char*) data, strlen((char *)data), NULL, NULL);
  result = HMAC(EVP_sha256(), (unsigned char*) key, strlen((char *)key),(unsigned char*) data, dataSize, NULL, NULL);
  int result_len =  strlen((char *)result);
  for (i = 0; i < result_len; i++) sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
  printf("\nHMAC_SHA256 = %s\nOK, result length %d\n", (char*)res_hexstring, result_len);
  return (unsigned char*)result;
 }

//======================================================== handleErrors
void handleErrors(void){
    unsigned long errCode;
    printf("An error occurred\n");
    while((errCode = ERR_get_error())){
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}

//======================================================== encryptAES
int encryptAES(unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;
    if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL))
        handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL)) handleErrors();
    if(plaintext){
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();
        ciphertext_len = len;
    }
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


//======================================================== main
//========================================================
int main(int arc, char *argv[]) {
     OpenSSL_add_all_algorithms();
	 ERR_load_crypto_strings();    
   
     printf("\n========================================\n");
	 printf("==========  ΑΠΟΣΤΟΛΕΑΣ  ================\n");
	 printf("========================================\n");
	 
	 // Διαβάζουμε το δημόσιο κλειδί από το δίσκο και το αποθηκεύουμε στη μεταβλητή rsaPublic
	 printf("\nReading public key...\n");
     char * publicKeyFilename = argv[1];     // H πρώτη παράμετρος είναι το δημόσιο κλειδί. Default = public.pem
	 if (publicKeyFilename==NULL) publicKeyFilename = (char*) "public.pem";
	 FILE * file = fopen(publicKeyFilename, "rb");
	 RSA* rsaPublic = RSA_new();
	 rsaPublic = PEM_read_RSA_PUBKEY(file, &rsaPublic, nullptr, nullptr);
	 printRSA(rsaPublic,0);
	 
	 // Διαβάζουμε το μήνυμα  που θέλουμε να κρυπτογραφήσουμε. Για την εργασία είναι το κλειδί key32
     // Μπορούμε να το ορίσουμε και από τον κώδικα ενεργοποιώντας την απενεργοποιημένη γραμμή παρακάτω
	 printf("\nReading key...\n");
	 //unsigned char * msg = readFile((char*) "key32"); 
	 static const unsigned char  msg[] ="12345678901234567890123456789012";
	 int keySize=strlen((char*)msg);
	 printf("\nkey size=%d\n",keySize);
	 BIO_dump_fp(stdout, (const char *)msg,keySize );
     
     // Κρυπτογραφούμε το κλειδί με RSA
     //char* encrypt = (char*) malloc(RSA_size(rsaPublic));
	 unsigned char encrypt[256];    // buffer για αποθήκευση του μηνύματος
	 int encrypt_len;
     char *err = (char*) malloc(130);
	 if((encrypt_len = RSA_public_encrypt(strlen((const char*)msg), (unsigned char*)msg,encrypt,
                                         rsaPublic, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        return 1;
    }
	 //for (int i=keySize;i<encrypt_len;i++) (unsigned char*) encrypt[]
	 printf("\nEncrypted text");
	 printf("\nencryptLen=%d\n", encrypt_len);                   // εκτυπώνουμε το κρυπτογραφημένο κλειδί
 	 BIO_dump_fp(stdout, (const char *)encrypt, encrypt_len);


	
    //Γράφουμε το κρυπτογραφημένο μήνυμα στο δίσκο
    FILE *out = fopen("rsaOut.text", "w");
    // fwrite(encrypt, sizeof(*encrypt),  RSA_size(rsaPublic), out);
	fwrite(encrypt, sizeof(*encrypt),encrypt_len, out);
    fclose(out);
    printf("Encrypted message written to file: rsaOut.text\n");
        
	    //Υπολογίζουμε το SHA-256 
		printf("\n\n------------------- SHA-256 ------------------");
	    //char* hmacText = HMAC(EVP_sha256(), (unsigned char *) msg, strlen((char*)msg),(unsigned char*) "encrypt", strlen(( char *)"encrypt"), NULL, NULL);
		char shaText[256];
		unsigned char * hmacText = getHMAC((unsigned char *)msg,(unsigned char *)encrypt,keySize);
		int  hmacText_len= strlen((char*) hmacText);
		printf("hmacText_len=%d\n",hmacText_len);
		printf("hmacText is:\n");
		BIO_dump_fp(stdout, (const char *)hmacText, hmacText_len);
		
		//Κρυπτογραφούμε το αποτέλεσμα με AES
		
		
		printf("\n\n------------------- AES ------------------\n");
		char* aesEncryptedText = (char*) malloc(1024); 
		int aesEncryptedSize = encryptAES((unsigned char*)hmacText , strlen((char*) hmacText), (unsigned char *)msg, (unsigned char *) aesEncryptedText);
		printf("/naesEncryptedTextLen=%d\n", aesEncryptedSize);
		BIO_dump_fp(stdout, (const char *)aesEncryptedText, aesEncryptedSize);
		
		
		  //Γράφουμε το κρυπτογραφημένο μήνυμα στο δίσκο
		FILE *out2 = fopen("aesOut.text", "w");
		fwrite(aesEncryptedText, sizeof(*aesEncryptedText),aesEncryptedSize, out2);
		fclose(out2);
		printf("AES Encrypted message written to file: aesOut.text .\n");
        
	
		
	//=============================================
	RSA_free(rsaPublic);
	free(err);
   
    return 0;
}