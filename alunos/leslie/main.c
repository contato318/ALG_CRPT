#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <locale.h>
#define DEBUG 1



void LerArquivo() {

        char url[40];
        char ch;
        FILE *arq;
	if (DEBUG) printf ("--------------------ENTRANDO NA FUNÇÃO DE LerArquivo--------------------\n");
        printf ("ESCREVA O NOME DO ARQUIVO: ");
	scanf(" %s",url);
		
        arq = fopen(url, "r");
        if(arq == NULL){
            printf("ERRO! NÃO FOI POSSÍVEL ABRIR O ARQUIVO.\n");
	
	    system("break");
		    
       } else {
            while( (ch=fgetc(arq))!= EOF )
                putchar(ch);

        fclose(arq);
	printf("\n");
       }		
	if (DEBUG) printf ("--------------------SAINDO DA FUNÇÃO DE LerArquivo--------------------\n\n");
        

    }


void BoasVindas() {
	if (DEBUG) printf ("--------------------ENTRANDO NA FUNÇÃO DE BoasVindas--------------------\n");
	
	printf("SEJA BEM VINDO!!!\n");
	
	if (DEBUG) printf ("--------------------SAINDO DA FUNÇÃO DE BoasVindas--------------------\n\n");
	

    }

void MensagemSaida() {
	if (DEBUG) printf ("--------------------ENTRANDO NA FUNÇÃO DE MensagemSaida--------------------\n");
        
	printf ("MENSAGEM DE SAÍDA: OBRIGADO!\n");
	
	if (DEBUG) printf ("--------------------SAINDO DA FUNÇÃO DE MensagemSaida--------------------\n\n");
        

    }

	struct mensagem env_criptografar (const unsigned char * conteudo_arquivo,unsigned long long int tamanho_corpo,unsigned int chave );
	//ESTRUTURA PARA COLOCAR O CONTEUDO DO ARQUIVO
	struct mensagem 
		{ 
		unsigned long long int tamanho; 
		unsigned char * conteudo;
		unsigned int chave;
		};

	
void Criptografar() {
	if (DEBUG) printf ("--------------------ENTRANDO NA FUNÇÃO DE Criptografar--------------------\n");
			
	//utilizado para receber o retorno da mensagem
	struct mensagem msg_testeEscura; 
    	FILE *fp;
	unsigned char * corpo;
    	unsigned long long int lSize;
	unsigned int chaveI;
    	char arquivo1[50],arquivo2[50],chaveS[10];
	int i, tam;


		printf("\nDigite a chave para criptografar o arquivo:");
		scanf(" %s",chaveS);
		tam = strlen(chaveS);

		for(i=0; i <= tam; i++){
			chaveI=(chaveI+chaveS[i]);
		}	
    		printf("\nDigite o nome do arquivo de origem:");
    		scanf(" %s",arquivo1);
    		printf("\nDigite o nome do arquivo de destino:");
    		scanf(" %s",arquivo2);

			fp = fopen (arquivo1 , "rb" );
			if( !fp )  perror("teste_entradaPUNK.txt"),fprintf(stderr, "Falha em: %d - %s\n", __LINE__,__FILE__),exit(1);
			fseek( fp , 0L , SEEK_END);
			lSize = ftell( fp );
			rewind( fp );
			corpo = (unsigned char *)calloc( lSize+1, sizeof(unsigned char));
			if( !corpo ) fclose(fp),fprintf(stderr, "Erro ao obter memoria %d - %s\n", __LINE__,__FILE__),exit(1);
			if( 1!=fread( corpo , lSize, 1 , fp) )
			fclose(fp),free(corpo),fputs("Falha ao realizar a leitura",stderr),exit(1);
            
            
        //criptografando
        msg_testeEscura=env_criptografar(corpo,lSize,chaveI);            
            
        FILE *fpOut;
			fpOut = fopen (arquivo2 , "wb" );
			if( !fpOut )  perror(arquivo2),exit(1);
			fwrite(msg_testeEscura.conteudo, 1, msg_testeEscura.tamanho, fpOut);
		
        fclose(fpOut);

	if (DEBUG) printf ("\n--------------------SAINDO DA FUNÇÃO DE Criptografar--------------------\n\n");

}


struct mensagem env_criptografar (const unsigned char * conteudo_arquivo,unsigned long long int tamanho_corpo,unsigned int chave ){
    	unsigned long long int count;

    	//utilizado para receber o retorno da mensagem
	struct mensagem msg_testeEscura;     
    	msg_testeEscura.tamanho=tamanho_corpo;
    	msg_testeEscura.conteudo=conteudo_arquivo;
	msg_testeEscura.chave=chave;
            
            	for (count = 0 ; count <= msg_testeEscura.tamanho; count ++){
                	//printf("\n%c",msg_testeEscura.conteudo[count]);
                	msg_testeEscura.conteudo[count]=((int)msg_testeEscura.conteudo[count]+msg_testeEscura.chave)%256;
            	}	
        
     		return (msg_testeEscura);

}

	struct mensagem env_decriptografar (const unsigned char * conteudo_arquivo,unsigned long long int tamanho_corpo,unsigned int chave );
		

void Decriptografar() {
	if (DEBUG) printf ("--------------------ENTRANDO NA FUNÇÃO DE Decriptografar--------------------\n");
			
	//utilizado para receber o retorno da mensagem
	struct mensagem msg_testeEscura; 
    	FILE *fp;
	unsigned char * corpo;
    	unsigned long long int lSize;
	unsigned int chaveI;
    	char arquivo1[50],arquivo2[50],chaveS[10];
	int i, tam;


		printf("\nDigite a chave para decriptografar o arquivo:");
		scanf(" %s",chaveS);
		tam = strlen(chaveS);

		for(i=0; i <= tam; i++){
			chaveI=(chaveI+chaveS[i]);
		}	
    		printf("\nDigite o nome do arquivo de origem:");
    		scanf(" %s",arquivo1);
    		printf("\nDigite o nome do arquivo de destino:");
    		scanf(" %s",arquivo2);

			fp = fopen (arquivo1 , "rb" );
			if( !fp )  perror("teste_entradaPUNK.txt"),fprintf(stderr, "Falha em: %d - %s\n", __LINE__,__FILE__),exit(1);
			fseek( fp , 0L , SEEK_END);
			lSize = ftell( fp );
			rewind( fp );
			corpo = (unsigned char *)calloc( lSize+1, sizeof(unsigned char));
			if( !corpo ) fclose(fp),fprintf(stderr, "Erro ao obter memoria %d - %s\n", __LINE__,__FILE__),exit(1);
			if( 1!=fread( corpo , lSize, 1 , fp) )
			fclose(fp),free(corpo),fputs("Falha ao realizar a leitura",stderr),exit(1);
            
            
        //decriptografando
        msg_testeEscura=env_decriptografar(corpo,lSize,chaveI);            
            
        FILE *fpOut;
			fpOut = fopen (arquivo2 , "wb" );
			if( !fpOut )  perror(arquivo2),exit(1);
			fwrite(msg_testeEscura.conteudo, 1, msg_testeEscura.tamanho, fpOut);
		
        fclose(fpOut);

	if (DEBUG) printf ("\n--------------------SAINDO DA FUNÇÃO DE Decriptografar--------------------\n\n");

}


struct mensagem env_decriptografar (const unsigned char * conteudo_arquivo,unsigned long long int tamanho_corpo,unsigned int chave ){
    	unsigned long long int count;

    	//utilizado para receber o retorno da mensagem
	struct mensagem msg_testeEscura;     
    	msg_testeEscura.tamanho=tamanho_corpo;
    	msg_testeEscura.conteudo=conteudo_arquivo;
	msg_testeEscura.chave=chave;
            
            	for (count = 0 ; count <= msg_testeEscura.tamanho; count ++){
                	//printf("\n%c",msg_testeEscura.conteudo[count]);
                	msg_testeEscura.conteudo[count]=((int)msg_testeEscura.conteudo[count]-msg_testeEscura.chave)%256;
            	}	
        
     		return (msg_testeEscura);

}


	



int Menu(){
    
    if (DEBUG) printf ("--------------------ENTRANDO NA FUNÇÃO MENU--------------------\n");
    setbuf(stdin, NULL);
    int continuar=1;
    do
    {
        printf("[1]. Criptografar\n");
        printf("[2]. Decriptografar\n");
        printf("[3]. Ler Arquivo\n");
        printf("[0]. Sair\n");

        scanf(" %d", &continuar);
        system("clear");

        switch(continuar)
        {
            case 1:
                Criptografar();
                break;

            case 2:
                Decriptografar();
                break;

            case 3:
                LerArquivo();
                break;

            case 0:
                MensagemSaida();
                break;

            default:
                
                printf("DIGITE UMA OPÇÃO VÁLIDA!\n");
        }
    } while(continuar);
    if (DEBUG) printf ("--------------------SAINDO DA FUNÇÃO MENU--------------------\n\n");
}


int main(void)
{
	system("clear");

	BoasVindas();

	Menu();

	
        return 0;
}
