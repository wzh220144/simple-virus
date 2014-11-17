#include <stdio.h>

char t[3];

char *toHex(unsigned int a) {
	t[2] = 0;
	t[0] = a/16;
	if(t[0] < 10)
		t[0] = t[0] +'0';
	else t[0] = t[0] - 10 + 'a';
	t[1] = a%16;
	if(t[1] < 10)
		t[1] = t[1] +'0';
	else t[1] = t[1] - 10 + 'a';
	return t;
}

int main() {
	FILE *f;
	f = fopen("test", "r");
	unsigned char c;
	int a;
	printf("char shellcode[]=");
	printf("\"");
	while(1) {
		a=fscanf(f, "%c", &c);
		if(a==EOF)
			break;
		
		printf("\\x%s", toHex(c));
	}
	printf("\"");
	printf(";");
	fclose(f);
}