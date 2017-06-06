#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int main (void){
        //gerando dois valores baseados no tempo de execucao do programa
        time_t clk = time(0);
        unsigned int tempo1=0,tempo2=0, tempo3=0, tempo4=0;

        //brincando um pouco com os valores
        tempo1 = clk / 256;
        tempo2 = clk % 256;
        tempo3 = (tempo1 * tempo2) % 256;
        tempo4 = (tempo3 + tempo2) % 256;


        // mostrando os valores
        printf ("\nTempo coletado: %i",(int)clk);
        printf ("\nPrimeiro VALOR: %i", tempo1);
        printf ("\nSegundo VALOR:  %i", tempo2);
        printf ("\nTerceiro VALOR: %i", tempo3);
        printf ("\nQuarto VALOR: %i",  tempo4);

        //Usando randomico
        unsigned int x_randomico = 0, y_randomico = 0;

        //gerando uma semente:
        srand( (unsigned)time(NULL) );

        x_randomico = rand() % 256;

        //gerando outra semente:
        srand( (unsigned)time(NULL) + tempo3 * tempo4 );
        y_randomico = rand() % 256;

        //apresentando os dois randomicos:
        printf ("\n\n Primeiro Rand: %i", x_randomico);
        printf ("\n Segundo Rand: %i", y_randomico);

        return (0);

}
