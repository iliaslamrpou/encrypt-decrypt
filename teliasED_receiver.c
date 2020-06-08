/* =======================================================
			       ENCRYPT - DECRYPT RSA
	Copyright (c) 2020 by Ilias Lamprou & Telis Zacharis
				    All rights reserved
     GitHub: https://github.com/iliaslamrpou/encrypt-decrypt
  ========================================================

	Πριν τρέξετε αυτόν τον κώδικα τοποθετήστε στον ίδιο φάκελλο το ιδιωτικό 
	κλειδί τo οποίo θα πρέπει να έχει το όνομα private.key 
	
	Με εκτέλεση του αρχείου χωρίς παραμέτρους, αυτό θα προσπαθήσει να 
	διαβάσει τα αρχεία private.key
	Για να φορτώσετε αρχεία με άλλο όνομα η σύνταξη είναι:
	
	teliasED privateKeyName

	Ο κώδικας παίζει τον ρόλο του παραλήπτη και διαβάζει τα αρχεία 
	που έχουν σταλεί από τον αποστολέα καθώς και το ιδιωτικό κλειδί	
	και αν το κλειδί που έστειλε ο αποστολέας δεν έχει αλλοιωθεί 
	βγάζει μήνυμα επιβεβαίωσης και αποθηκεύει το κλειδί του 
	αποστολέα με το όνομα sender.key
*/


#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <string.h>
#define KEY_LENGTH 8182//768 


#include <fstream>
//#include <streambuf>
#include <sstream>
  
 

//======================================================== loadFile
// Διαβάζει ένα αρχείο από δλισκο και επιστρέφει έναn pointer σε char arrray
// Χρησιμοποιείται για την ανάγνωση των αρχείων που στέλνει ο αποστολέας 
// καθώς και για την ανάγνωση του κλειδιού του αποστολέα όταν δεν επιθυμούμε να 
// οριστεί από τον κώδικα

unsigned char* readFile2(char* filename){   // bug fixes

	std::ifstream t(filename);
	std::stringstream buffer;
	buffer << t.rdbuf();
    return (unsigned char*) buffer.str().c_str();
}
//------------------------------------
  unsigned char* readFile(char* filename){
  FILE* f = fopen(filename, "r");
   fseek(f, 0, SEEK_END);
   size_t size = ftell(f);
   printf("\n filesize for read =%d\n",size);
   unsigned char* buf = (unsigned char*)malloc(size+1);
  // unsigned char* buf = new unsigned  char[size];
   rewind(f);
   fread(buf, sizeof(char), size, f);
   return buf;
}

//======================================================== printRSA
// Εκτυπώνει ένα κλειδί το οποίο είναι σε μορφή RSA

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
// Κάνει hash το κείμενο data χρησιμοποιώντας το κλειδί key
// και επιστρέφει το αποτέλεσμα

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

//======================================================== decryptAES
int decryptAES(unsigned char *ciphertext, int ciphertext_len, 
            const unsigned char *key, 
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL))
        handleErrors();

    /* Initialise key */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL)) handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}


//======================================================== main
//========================================================
int main(int arc, char *argv[]) {
     OpenSSL_add_all_algorithms();
	 ERR_load_crypto_strings();    
     char *err = (char*) malloc(130);
    
	 printf("\n========================================\n");
	 printf("==========  ΠΑΡΑΛΗΠΤΗΣ  ================\n");
	 printf("========================================\n");
	
	 //Διαβάζουμε το ιδιωτικό κλειδί
	 printf("\nReading private key...\n");
	 char * privateKeyFilename = argv[1];     // H δεύτερη παράμετρος είναι το ιδιωτικό κλειδί. Default = private.key
	 if (privateKeyFilename==NULL) privateKeyFilename = (char*) "private.key";
	
	 FILE * file2 = fopen(privateKeyFilename, "rb");
	 RSA* rsaPrivate = RSA_new();
	 rsaPrivate = PEM_read_RSAPrivateKey(file2, &rsaPrivate, nullptr, nullptr);
	 printRSA(rsaPrivate,1);
	 
	 // Διαβάζουμε από το δίσκο το κρυπτογραφημένο μήνυμα (κλειδί) που μας έχει σταλεί
     unsigned char * encryptedMsg = readFile((char*) "rsaOut.text"); 
	 //printf(".loaded encrypted key=\n%s\n",(unsigned char*) encryptedMsg);
	 int encryptedMsgLen = strlen((char*)encryptedMsg);
	 printf("/nencryptLen=%d\n", encryptedMsgLen);                   // εκτυπώνουμε το κρυπτογραφημένο κλειδί
 	 BIO_dump_fp(stdout, (const char *)encryptedMsg, encryptedMsgLen);


    // Κάνουμε decrypt
     char* decrypt = (char*) malloc(encryptedMsgLen-1);
	 printf("1.decrypt=\n%s\n",(unsigned char*) decrypt);
	 memset((char*) decrypt, 0 ,encryptedMsgLen-1);
	 printf("2.decrypt=\n%s\n",(unsigned char*) decrypt);
	
    int decryptedLen =(RSA_private_decrypt(encryptedMsgLen, (unsigned char*)encryptedMsg, (unsigned char*)decrypt,rsaPrivate, RSA_PKCS1_OAEP_PADDING) == -1);
	if (decryptedLen==1){
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        return 1;
    }
	decryptedLen =strlen((char *)decrypt);
	printf("/nedecryptLen=%d\n", decryptedLen);                   // εκτυπώνουμε το κρυπτογραφημένο κλειδί
 	BIO_dump_fp(stdout, (const char *)decrypt,decryptedLen );
    printf("Decrypted message: %s\n", decrypt);
    
    printf("\n\n------------------- Παραλήπτης SHA-256 ------------------");
	unsigned char * hmacText2 = getHMAC((unsigned char *)decrypt,(unsigned char *)encryptedMsg,decryptedLen);
     int hmacText_len2 = strlen((char*) hmacText2);
	 printf("hmacText_len2=%d\n",hmacText_len2);
	 printf("hmacText2 is:\n");
	 BIO_dump_fp(stdout, (const char *)hmacText2, hmacText_len2);		
	
	 printf("\n\n------------------- Παραλήπτης AES decrypt ------------------");
	 // Διαβάζουμε από το δίσκο το κρυπτογραφημένο μήνυμα (κλειδί) που μας έχει σταλεί
     unsigned char * aes_encryptedMsg = readFile2((char*) "aesOut.text"); 
	// printf("\nloaded aes_encrypted key=\n%s\n",(unsigned char*) aes_encryptedMsg);
	 int aes_encryptedMsgLen = strlen((char*)aes_encryptedMsg);
	 printf("\naes_encryptLen=%d\n", aes_encryptedMsgLen);                   // εκτυπώνουμε το κρυπτογραφημένο κλειδί
 	 BIO_dump_fp(stdout, (const char *)aes_encryptedMsg, aes_encryptedMsgLen);

     //unsigned char* aesDecryptedText = new unsigned  char[1024];
      char* aesDecryptedText = (char*) malloc(1024); 
	 
     int aesDecryptedText_len= decryptAES((unsigned char*)aes_encryptedMsg, aes_encryptedMsgLen,(unsigned char *)decrypt,(unsigned char *)aesDecryptedText);
     printf("\naesDecryptedText_len=%d\n", aesDecryptedText_len);                   // εκτυπώνουμε το κρυπτογραφημένο κλειδί
 	 BIO_dump_fp(stdout, (const char *)aesDecryptedText, aesDecryptedText_len);
	
	
	if(strncmp((char*) aesDecryptedText,(char*) hmacText2, aesDecryptedText_len ) == 0 ) {
		printf("\n\nThe files are equal.\n\nThe key is correct!!!!!!!");
		//Γράφουμε το κλειδί του αποστολέα στο δίσκο
		FILE *out3 = fopen("sender.key", "w");
		fwrite(decrypt, sizeof(*decrypt),decryptedLen, out3);
		fclose(out3);
		printf("\n\nEncrypted message written to file: sender.key\n");
        
		
	}
	else printf("The files are not equal.");
		
	//=============================================
	RSA_free(rsaPrivate);
    free(decrypt);
    free(err);
	free(aesDecryptedText);
   
    return 0;
}