/*

EXEMPLO SIMPLES DE CRIPTOGRAFIA ASSIMÉTRICA (RSA)
UTILIZANDO OPENSSL

Basicamente exemplifica:
    - Criação de chaves
    - Cifração e Decifração RSA

*/



#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define KEY_LENGTH  2048
#define PUB_EXP     65537

struct keyAss{
    unsigned char   *conteudo;
    int tamanho;
};


int ASS_gera_chaves_assimetricas(const char * pass, const char * nome_pub, const char * nome_pvt);
struct keyAss ASS_enc(const char * nome_pub,const unsigned char * msg);
struct keyAss ASS_dec(const char * pass,const char * nome_pvt,const struct keyAss msg);

int main(void) {

    char resp;
    char chavePublica[20];
    char chavePrivada[20];
    char senha[32];

    printf("\nDeseja gerar novas chaves? (s-n)");
    scanf(" %c",&resp);
    while(resp!='s'&&resp!='n'){
            printf("\nInvalido. Informe novamente");
            printf("\nDeseja gerar novas chaves? (s-n)");
            scanf(" %c",&resp);
    }
    if(resp=='s'){
         printf("Informe o nome para a chave privada: ");
         fflush(stdin);fgets(chavePrivada, KEY_LENGTH-1, stdin);
         chavePrivada[strlen(chavePrivada)-1] = '\0';

         printf("\nInforme o nome para a chave publica: ");
         fflush(stdin);fgets(chavePublica, KEY_LENGTH-1, stdin);
         chavePublica[strlen(chavePublica)-1] = '\0';

         printf("\nInforme a senha: ");
         fgets(senha, KEY_LENGTH-1, stdin);
         senha[strlen(senha)-1] = '\0';

         if (ASS_gera_chaves_assimetricas(senha,chavePublica,chavePrivada)){
            char bufferError[120];
            ERR_error_string(ERR_get_error(), bufferError);
            fprintf(stderr, "Erro ao gerar as chaves: %s", bufferError);
        }else{
            printf("\nChaves geradas");
        }
    }

    unsigned char   msg[KEY_LENGTH/8];  // Message to encrypt
    struct keyAss mensagemK;

    // obtendo a mensagem
    printf("\nInforme a mensagem a ser criptografada: ");
    fflush(stdin);fgets(msg, KEY_LENGTH-1, stdin);
    msg[strlen(msg)-1] = '\0';

    //criptografando
         printf("\nIremos criptografar, para isto, informe o nome para a chave publica: ");
         fflush(stdin);fgets(chavePublica, KEY_LENGTH-1, stdin);
         chavePublica[strlen(chavePublica)-1] = '\0';



    mensagemK=ASS_enc(chavePublica, msg);
    printf("MSG Cifrada:: [%s]\n\n", mensagemK.conteudo);



         printf("\nIremos descriptografar, para isto, informe o nome para a chave PRIVADA: ");
         fflush(stdin);fgets(chavePrivada, KEY_LENGTH-1, stdin);
         chavePrivada[strlen(chavePrivada)-1] = '\0';


         printf("Informe a senha: ");
         fflush(stdin);fgets(senha, KEY_LENGTH-1, stdin);
         senha[strlen(senha)-1] = '\0';

    mensagemK=ASS_dec(senha,chavePrivada, mensagemK);
    printf("Decifrado:: [%s]\n", mensagemK.conteudo);

    return 0;
}
struct keyAss ASS_dec(const char * pass,const char * nome_pvt,const struct keyAss msg){
    struct keyAss retorno;

        //ABRINDO A CHAVE
            FILE *fp;
			unsigned int lSize;
            unsigned char*  chavePrivadaArquivo;
			fp = fopen ( nome_pvt , "rb" );
			if( !fp )  perror(nome_pvt),exit(1);
			fseek( fp , 0L , SEEK_END);
			lSize = ftell( fp );
			rewind( fp );
			chavePrivadaArquivo = (unsigned char *)calloc( lSize+1, sizeof(unsigned char));
			if( !chavePrivadaArquivo ) fclose(fp),fputs("falha para alocar memoria...",stderr),exit(1);
			if( 1!=fread( chavePrivadaArquivo , lSize, 1 , fp) )
			  fclose(fp),free(chavePrivadaArquivo),fputs("Falha ao realizar a leitura",stderr),exit(1);
			fclose(fp);

            int cCriptChave;
            for(cCriptChave=0;cCriptChave<lSize;cCriptChave++){
                chavePrivadaArquivo[cCriptChave]=(chavePrivadaArquivo[cCriptChave]-127)%256;
            }

            BIO *bio2 = BIO_new_mem_buf((void*)chavePrivadaArquivo, (int)strlen(chavePrivadaArquivo));
            RSA *rsa_privatekey_file = PEM_read_bio_RSAPrivateKey(bio2, NULL, 0, NULL);

     char err[130];
    retorno.conteudo = malloc(msg.tamanho);
    if(RSA_private_decrypt(msg.tamanho, (unsigned char*)msg.conteudo, (unsigned char*)retorno.conteudo,
                           rsa_privatekey_file, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    }



    return retorno;
}

struct keyAss ASS_enc(const char * nome_pub,const unsigned char * msg){
        struct keyAss retorno;
    // abrindo chave
        RSA *keyPublic = NULL;
        keyPublic = RSA_new();
        BIO *chave_publica2 = NULL;
        chave_publica2 = BIO_new_file(nome_pub, "r");
        keyPublic = PEM_read_bio_RSAPublicKey(chave_publica2, NULL,0,NULL);
        if (keyPublic == 0) {
            char buffer[120];
            ERR_error_string(ERR_get_error(), buffer);
            fprintf(stderr, "Erro ao ler as chaves: %s", buffer);
            exit(1);
        }


        //criptografando
    retorno.conteudo = malloc(RSA_size(keyPublic));
    char err[130];
    if((retorno.tamanho = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)retorno.conteudo,
                                         keyPublic, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Erro ao criptografar a mensagem: %s\n", err);
        exit(1);
    }


            RSA_free(keyPublic);
            BIO_free_all(chave_publica2);


    return retorno;
}

int ASS_gera_chaves_assimetricas(const char * pass, const char * nome_pub, const char * nome_pvt){
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key


    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);


    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = malloc(pri_len + 1);
    pub_key = malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
PEM_write_bio_RSAPrivateKey(pri, keypair,EVP_des_ede3_cbc(),(unsigned char *)pass,strlen(pass),NULL,NULL);

    //cifrando a privada (aqui vc deverá usa A SUA CRIFRA SIMÉTRICA!!!!!!)
    // NECESSÁRIO ALTERAR!
     unsigned int cCriptChave=0;
    for(cCriptChave=0;cCriptChave<pri_len;cCriptChave++){
        pri_key[cCriptChave]=(pri_key[cCriptChave]+127)%256;
    }


    FILE *fpOut;
    fpOut = fopen ( nome_pvt , "wb" );
    if( !fpOut )  perror(nome_pvt),exit(1);
    fwrite(pri_key, 1, pri_len, fpOut);
    fclose(fpOut);

    FILE *fpOut2;
    fpOut2 = fopen ( nome_pub , "wb" );
    if( !fpOut2 )  perror(nome_pub),exit(1);
    fwrite(pub_key, 1, pub_len, fpOut2);
    fclose(fpOut2);

            RSA_free(keypair);
            BIO_free_all(pub);
            BIO_free_all(pri);
            free(pri_key);
            free(pub_key);

    return 0;
}
