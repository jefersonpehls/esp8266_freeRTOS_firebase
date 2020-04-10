#include <stdio.h>
#include <stdlib.h>



struct no 
{
	int num;
	struct no* prox;
}; 

typedef struct no No;

No* criar_no ()
{
	No* novo = (No*) malloc(sizeof(No));
	return novo;
}


No* inserir_no_inicio (No* Lista, int dado) 
{
	No* novo_no = criar_no();
	novo_no->num=dado;
	
	if (Lista == NULL) 
	{
		Lista = novo_no;
		novo_no->prox=NULL;
	}
	
	else 
	{
		novo_no->prox = Lista;
		Lista = novo_no;	
	}
	
	return Lista;
	
}


void imprimir_lista (No* Lista) 
{
	No* aux = Lista;
	
	while  (aux != NULL) 
	{
		printf("%d...", aux->num);
		aux=aux->prox;	//incremento
	}
	
}



int main()
{
	No* Lista = NULL;
	Lista = inserir_no_inicio(Lista,10);
	Lista = inserir_no_inicio(Lista,20);
	Lista = inserir_no_inicio(Lista,30);
	imprimir_lista(Lista);
    return 0;
}











