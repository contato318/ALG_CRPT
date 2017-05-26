#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <malloc.h>
#define DEBUG 0

void msgBoasVindas(void);
int msgSaida(void);
void setarAcentuacao(void);
int lerArquivo();
int menuUsuario();
void criptografar();
void decriptografar();
struct mensagem env_criptografar (const unsigned char * conteudo_arquivo,unsigned long long int tamanho_corpo, unsigned int chave );
struct mensagem env_decriptografar (const unsigned char * conteudo_arquivo,unsigned long long int tamanho_corpo, unsigned int chave );

//ESTRUTURA PARA COLOCAR O CONTEUDO DO ARQUIVO
struct mensagem
{
	unsigned long long int tamanho;
	unsigned char * conteudo;
	unsigned int chave;
};

int main(void){
    setarAcentuacao();
    menuUsuario();
}

void msgBoasVindas(void){
    if (DEBUG) printf ("\nEntrando na função de msgBoasVindas");
    printf("\n************************************************************");
    printf("\n                 Criptografia de Arquivo");
    printf("\n************************************************************");
    if (DEBUG) printf ("\nSaindo da função de msgBoasVindas");
}


int msgSaida(){
    if (DEBUG) printf ("\nEntrando na função de msgSaida");
    printf("\n*******************");
    printf("\n      Adeus!");
    printf("\n*******************");
    getchar();
    if (DEBUG) printf ("\nSaindo da função de msgSaida");
    return (0);
}

int lerArquivo(){
    msgBoasVindas();

    if (DEBUG) printf ("\nEntrando na função de lerArquivo");
    char str[50];
    printf("\nDigite o nome do arquivo:");
    scanf(" %s",str);
	char ch;
	FILE *arq;

	arq = fopen(str, "r");
	if(arq == NULL){
	    printf("\nErro, não foi possível abrir o arquivo\n");
	    system("pause");
	    system("CLS");
	    msgBoasVindas();
	}else{
        printf("\n");
	    while( (ch=fgetc(arq))!= EOF )
		    putchar(ch);
	    fclose(arq);
	    printf("\n");
	    system("pause");
	    system("CLS");
	    msgBoasVindas();
     }
    if (DEBUG) printf ("\nSaindo da função de lerArquivo");
	return 0;
}

void setarAcentuacao(){
    if (DEBUG) printf ("\nEntrando na função de setarAcentuacao");
    setlocale(LC_ALL, "Portuguese");
    if (DEBUG) printf ("\nSaindo da função de setarAcentuacao");
}

int menuUsuario(){
    system("CLS");
    msgBoasVindas();
    if (DEBUG) printf ("\nEntrando na função de menuUsuario");
    setbuf(stdin, NULL);
    int continuar=1;
    do
    {
        printf("\n1. Criptografar");
        printf("\n2. Decriptografar");
        printf("\n3. Ler Arquivo");
        printf("\n0. Sair");

        scanf(" %d", &continuar);
        system("cls || clear");

        switch(continuar)
        {
            case 1:
                criptografar();
                break;

            case 2:
                decriptografar();
                break;

            case 3:
                lerArquivo();
                break;

            case 0:
                msgSaida();
                break;

            default:
                msgBoasVindas();
                printf("\nDigite uma opção valida!");
        }
    } while(continuar);
    if (DEBUG) printf ("\nSaindo da função de menuUsuario");
}

void criptografar(){

    struct mensagem msg_testeEscura; //utilizado para receber o retorno da mensagem
    FILE *fp;
	unsigned char * corpo;
    unsigned long long int lSize;
    unsigned int chaveI;
    char arquivo1[50], arquivo2[50], chaveS[50];
    int i, tam;

    msgBoasVindas();

	//Informando o caminho dos dois arquivos
    printf("\nDigite o nome do arquivo de origem:");
    scanf(" %s",arquivo1);
    printf("\nDigite o nome do arquivo de destino:");
    scanf(" %s",arquivo2);
    printf("\nDigite a chave para criptografar o arquivo:");
    scanf(" %s",chaveS);
    tam = strlen(chaveS);

    for(i=0; i <= tam; i++){
        chaveI=(chaveI+chaveS[i]);
    }

            //Abrindo o arquivo de origem
			fp = fopen (arquivo1 , "rb" ); //"rb" significa que o arquivo vai ser utilizado para leitura(r) em modo binário(b)
			if( !fp )  perror("Falha"),fprintf(stderr, "Falha em: %d - %s\n", __LINE__,__FILE__),exit(1); //Verifica se ocorreu falha ao abrir arquivo
			fseek( fp , 0L , SEEK_END); //Varre o arquivo até o final
			lSize = ftell( fp ); //Armazena o tamanho na variavel lSize
			rewind( fp );
			corpo = (unsigned char *)calloc( lSize+1, sizeof(unsigned char));
			if( !corpo ) fclose(fp),fprintf(stderr, "Erro ao obter memoria %d - %s\n", __LINE__,__FILE__),exit(1); //Verifica se ocorreu erro na alocação do arquivo para memoria
			if( 1!=fread( corpo , lSize, 1 , fp) )
			fclose(fp),free(corpo),fputs("Falha ao realizar a leitura",stderr),exit(1);

            //criptografando
            msg_testeEscura=env_criptografar(corpo,lSize,chaveI); //Passa o corpo, o tamanho do arquivo para a estrutura env_criptografar e a chave

            FILE *fpOut;
			fpOut = fopen (arquivo2 , "wb" );
			if( !fpOut )  perror(arquivo2),exit(1);
			fwrite(msg_testeEscura.conteudo, 1, msg_testeEscura.tamanho, fpOut);

            fclose(fpOut);

            printf("\nArquivo criptografado!\n");
            system("pause");
            system("CLS");
            msgBoasVindas();
}


struct mensagem env_criptografar (const unsigned char * conteudo_arquivo,unsigned long long int tamanho_corpo, unsigned int chave){
    unsigned long long int count;
    struct mensagem msg_testeEscura; //utilizado para receber o retorno da mensagem

    msg_testeEscura.tamanho=tamanho_corpo;
    msg_testeEscura.conteudo=conteudo_arquivo;
    msg_testeEscura.chave=chave;

            for (count = 0 ; count <= msg_testeEscura.tamanho; count ++){
                msg_testeEscura.conteudo[count]=((int)msg_testeEscura.conteudo[count]+msg_testeEscura.chave)%256;
            }

     return (msg_testeEscura);
}

void decriptografar(){
    struct mensagem msg_testeEscura; //utilizado para receber o retorno da mensagem
    FILE *fp;
	unsigned char * corpo;
    unsigned long long int lSize;
    unsigned int chaveI;
    char arquivo1[50],arquivo2[50], chaveS[50];
    int i, tam;


    msgBoasVindas();

    printf("\nDigite o nome do arquivo de origem:");
    scanf(" %s",arquivo1);
    printf("\nDigite o nome do arquivo de destino:");
    scanf(" %s",arquivo2);
    printf("\nDigite a chave para decriptografar o arquivo:");
    scanf(" %s",chaveS);
    tam = strlen(chaveS);

    for(i=0; i <= tam; i++){
        chaveI=(chaveI+chaveS[i]);
    }

			fp = fopen (arquivo1 , "rb" );
			if( !fp )  perror("Falha"),fprintf(stderr, "Falha em: %d - %s\n", __LINE__,__FILE__),exit(1);
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

            printf("\nArquivo decriptografado!\n");
            system("pause");
            system("CLS");
            msgBoasVindas();
}

struct mensagem env_decriptografar (const unsigned char * conteudo_arquivo,unsigned long long int tamanho_corpo, unsigned int chave){
    unsigned long long int count;
    struct mensagem msg_testeEscura; //utilizado para receber o retorno da mensagem

    msg_testeEscura.tamanho=tamanho_corpo;
    msg_testeEscura.conteudo=conteudo_arquivo;
    msg_testeEscura.chave=chave;

            for (count = 0 ; count <= msg_testeEscura.tamanho; count ++){
                msg_testeEscura.conteudo[count]=((int)msg_testeEscura.conteudo[count]-msg_testeEscura.chave)%256;
            }

     return (msg_testeEscura);
}
