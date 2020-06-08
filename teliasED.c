/* =======================================================
			       ENCRYPT - DECRYPT RSA
	Copyright (c) 2020 by Ilias Lamprou & Telis Zacharis
				    All rights reserved
     GitHub: https://github.com/iliaslamrpou/encrypt-decrypt
  ========================================================
 
	Πριν τρέξετε αυτόν τον κώδικα τοποθετήστε στον ίδιο φάκελλο το δημόσιο 
	και ιδιωτικό κλειδί τα οποία τα πρέπει να έχουν τα ονόματα private.key 
	και public.pem
	
	Με εκτέλεση του αρχείου χωρίς παραμέτρους, αυτό θα προσπαθήσει να 
	διαβάσει τα αρχεία private.key και public.pem
	Για να φορτώσετε αρχεία με άλλο όνομα η σύνταξη είναι:
	
	teliasED publicKeyName privateKeyName

	Το πρώτο μέρος του προγράμματος είναι το κομμάτι του αποστολέα ενώ 
	το δεύτερο είναι του παραλήπτη
	Ο κώδικας ως αποστολέας δημιουργεί τα αρχεία rsaOut.txt και aesOut.txt 
	τα οποία θα πρέπει να αποστείλει ο αποστολέας στον παραλήπτη
	
	Το δεύτερο μέρος του κώδικα παίζει τον ρόλο του παραλήπτη και διαβάζει 
	αυτά τα αρχεία καθώς και το ιδιωτικό κλειδί	και αν το κλειδί που έστειλε 
	ο αποστολέας δεν έχει αλλοιωθεί βγάζει μήνυμα επιβεβαίωσης και αποθηκεύει 
	το κλειδί με το όνομα sender.key
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

unsigned char* readFile2(char* filename){   // bug fixes

	std::ifstream t(filename);
	std::stringstream buffer;
	buffer << t.rdbuf();
    return (unsigned char*) buffer.str().c_str();
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
        
	 printf("\n========================================\n");
	 printf("==========  ΠΑΡΑΛΗΠΤΗΣ  ================\n");
	 printf("========================================\n");
	
	 //Διαβάζουμε το ιδιωτικό κλειδί
	 printf("\nReading private key...\n");
	 char * privateKeyFilename = argv[2];     // H δεύτερη παράμετρος είναι το ιδιωτικό κλειδί. Default = private.key
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
	 //printf(".loaded aes_encrypted key=\n%s\n",(unsigned char*) aes_encryptedMsg);
	 int aes_encryptedMsgLen = strlen((char*)aes_encryptedMsg);
	 printf("\aes_encryptLen=%d\n", aes_encryptedMsgLen);                   // εκτυπώνουμε το κρυπτογραφημένο κλειδί
 	 BIO_dump_fp(stdout, (const char *)aes_encryptedMsg, aes_encryptedMsgLen);

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
	RSA_free(rsaPublic);
	RSA_free(rsaPrivate);
   // free(encrypt);
    free(decrypt);
	free(encryptedMsg);
	
    free(err);
   
    return 0;
}