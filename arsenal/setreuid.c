// EUID = Effective User ID = Usado na verificacao de acesso e para modificacao de arquivos (SETUID modifica o EUID para o ID do dono do processo em execucao, ex: passwd)
// RUID = Real User ID = ID que um user recebe ao logar, sendo que todo processo que eh spawnado por um usuario herda seu RUID. Portanto, para rodar comandos com a syscall system no contexto de um usuario X, eh necessario alterar o RUID para usuario X antes da chamada system (oq pode ser feito com setreuid/setregid).
// IMPORTANTE: Variaveis de ambiente nao sao modificadas apos setreuid/setregid... ou seja: variaveis PATH, HOME, SHELL, etc, continuam valendo para quem executar este binario.

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	setreuid(0,0);
	setregid(0,0);
	system("sh");
	return 0;
}
