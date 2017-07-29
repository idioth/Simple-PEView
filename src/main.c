#include <stdio.h>
#include <string.h>

char print_menu()
{
	printf("Simple PE View\n");
	printf("1. IMAGE_DOS_HEADER\n");
	printf("2. IMAGE_NT_HEADER\n");
	printf("3. IMAGE_SECTION_HEADER\n");
	return printf("> ");
}

int main(int argc, char *argv[])
{
	char filename[300];
	int select = 0;

	if (argc < 2)
	{
		printf("Usage: peveiw.exe file.exe\n");
		return 1;
	}

	strcpy_s(filename, sizeof(filename) / sizeof(char), argv[1]);
	init(filename);

	while (1)
	{
		print_menu();
		scanf_s("%d", &select);

		switch (select)
		{
		case 1:
			ShowDosHeader();
			break;
		case 2:
			ShowNTHeader();
			break;
		case 3:
			ShowSectionHeader();
			break;
		default:
			return 0;
		}
	}

	return 0;
}