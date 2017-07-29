#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <stddef.h>

IMAGE_DOS_HEADER		DosHeader;
IMAGE_FILE_HEADER		FileHeader;
IMAGE_SECTION_HEADER	*SectionHeader;
IMAGE_OPTIONAL_HEADER32	OptionalHeader;
// IMAGE_IMPORT_DESCRIPTOR	ImportDescriptor;

DWORD FileSize = 0;
DWORD PE_Signature = 0;
DWORD SectionOffset = 0;

char *CharacteristicsList[17];
int char_count = 0;
int NumberOfSections = 0;

void init(char *filename)
{
	FILE *fp;

	if (fopen_s(&fp, filename, "rb") != 0)
	{
		printf("[!] File Open Error!\n");
		return;
	}

	else
	{
		printf("[*] %s Open Success..\n", filename);
		fseek(fp, 0, SEEK_END);
		FileSize = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		fread_s(&DosHeader, sizeof(DosHeader), 1, sizeof(DosHeader), fp);
	}

	if (DosHeader.e_magic != 0x5a4d)
	{
		printf("[!] This is not pe file\n");
		fclose(fp);
		return 1;
	}

	fseek(fp, DosHeader.e_lfanew , SEEK_SET);
	fread(&PE_Signature, 1, sizeof(DWORD), fp);

	if (PE_Signature != 0x00004550)
	{
		printf("[!] This is not pe file\n");
		fclose(fp);
		return 1;
	}

	fread(&FileHeader, 1, sizeof(FileHeader), fp);

	SectionHeader = malloc(sizeof(IMAGE_SECTION_HEADER) * FileHeader.NumberOfSections);

	fread(&OptionalHeader, 1, FileHeader.SizeOfOptionalHeader, fp);

	SectionOffset = ftell(fp);

	int i = 0;
	while(i < FileHeader.NumberOfSections)
	{
		fread(&SectionHeader[i], 1, sizeof(IMAGE_SECTION_HEADER), fp);
		i++;
	}

	printf("[*] File Read Success..\n\n");
	fclose(fp);
	return 0;

}
void ShowDosHeader()
{
	printf("\n====================IMAGE_DOS_HEADER====================\n");
	printf("pFile\t\t Data\t\t Description\n");
	printf("%08X\t %04X\t\t Signature\n", offsetof(IMAGE_DOS_HEADER, e_magic), DosHeader.e_magic);
	printf("%08X\t %04X\t\t Bytes on Last Page of File\n", offsetof(IMAGE_DOS_HEADER, e_cblp), DosHeader.e_cblp);
	printf("%08X\t %04X\t\t Pages in File\n", offsetof(IMAGE_DOS_HEADER, e_cp), DosHeader.e_cp);
	printf("%08X\t %04X\t\t Relocations\n", offsetof(IMAGE_DOS_HEADER, e_crlc), DosHeader.e_crlc);
	printf("%08X\t %04X\t\t Size of Header in Paragraphs\n", offsetof(IMAGE_DOS_HEADER, e_cparhdr), DosHeader.e_cparhdr);
	printf("%08X\t %04X\t\t Minimum Extra Paragraphs\n", offsetof(IMAGE_DOS_HEADER, e_minalloc), DosHeader.e_minalloc);
	printf("%08X\t %04X\t\t Maximum Extra Paragraphs\n", offsetof(IMAGE_DOS_HEADER, e_maxalloc), DosHeader.e_maxalloc);
	printf("%08X\t %04X\t\t Initial (relative) SS\n", offsetof(IMAGE_DOS_HEADER, e_ss), DosHeader.e_ss);
	printf("%08X\t %04X\t\t Initial SP\n", offsetof(IMAGE_DOS_HEADER, e_sp), DosHeader.e_sp);
	printf("%08X\t %04X\t\t Checksum\n", offsetof(IMAGE_DOS_HEADER, e_csum), DosHeader.e_csum);
	printf("%08X\t %04X\t\t Initial IP\n", offsetof(IMAGE_DOS_HEADER, e_ip), DosHeader.e_ip);
	printf("%08X\t %04X\t\t Initial (relative) CS\n", offsetof(IMAGE_DOS_HEADER, e_cs), DosHeader.e_cs);
	printf("%08X\t %04X\t\t Offset to Relocation Table\n", offsetof(IMAGE_DOS_HEADER, e_lfarlc), DosHeader.e_lfarlc);
	printf("%08X\t %04X\t\t Overlay Number\n", offsetof(IMAGE_DOS_HEADER, e_ovno), DosHeader.e_ovno);
	for(int i=0; i<4; i++)
		printf("%08X\t %04X\t\t Signature\n", offsetof(IMAGE_DOS_HEADER, e_res[i]), DosHeader.e_res[i]);
	printf("%08X\t %04X\t\t OEM Identifier\n", offsetof(IMAGE_DOS_HEADER, e_oemid), DosHeader.e_oemid);
	printf("%08X\t %04X\t\t OEM Information\n", offsetof(IMAGE_DOS_HEADER, e_oeminfo), DosHeader.e_oeminfo);
	for(int i=0; i<10; i++)
		printf("%08X\t %04X\t\t Signature\n", offsetof(IMAGE_DOS_HEADER, e_res2[i]), DosHeader.e_res2[i]);
	printf("%08X\t %08X\t Offset to New EXE Header\n\n", offsetof(IMAGE_DOS_HEADER, e_lfanew), DosHeader.e_lfanew);
}

void ShowNTHeader()
{
	const fileoffset = DosHeader.e_lfanew + offsetof(IMAGE_NT_HEADERS32, FileHeader);
	const optionoffset = DosHeader.e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader);
	printf("\n====================IMAGE_NT_HEADERS====================\n");
	printf("Signature\n");
	printf("\tpFile\t\t Data\t\t Description\n");
	printf("\t%08X\t %08X\t Signature\n", DosHeader.e_lfanew, PE_Signature);

	printf("\nIMAGE_FILE_HEADER\n");
	printf("\tpFile\t\t Data\t\t Description\n");
	printf("\t%08X\t %04X\t\t Machine\n", fileoffset + offsetof(IMAGE_FILE_HEADER, Machine), FileHeader.Machine);
	printf("\t%08X\t %04X\t\t Number Of Sections\n", fileoffset + offsetof(IMAGE_FILE_HEADER, NumberOfSections), FileHeader.NumberOfSections);
	printf("\t%08X\t %08X\t Time Date Stamp\n", fileoffset + offsetof(IMAGE_FILE_HEADER, TimeDateStamp), FileHeader.TimeDateStamp);
	printf("\t%08X\t %08X\t Pointer To Symbol Table\n", fileoffset + offsetof(IMAGE_FILE_HEADER, PointerToSymbolTable), FileHeader.PointerToSymbolTable);
	printf("\t%08X\t %08X\t Number Of Symbols\n", fileoffset + offsetof(IMAGE_FILE_HEADER, NumberOfSymbols), FileHeader.NumberOfSymbols);
	printf("\t%08X\t %04X\t\t Size of Optional Header\n", fileoffset + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader), FileHeader.SizeOfOptionalHeader);
	printf("\t%08X\t %04X\t\t Characteristics\n", fileoffset + offsetof(IMAGE_FILE_HEADER, Characteristics), FileHeader.Characteristics);

	printf("\nIMAGE_OPTIONAL_HEADER\n");
	printf("\tpFile\t\t Data\t\t Description\n");
	printf("\t%08X\t %04X\t\t Magic\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, Magic), OptionalHeader.Magic);
	printf("\t%08X\t %02X\t\t Major Linker Version\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, MajorLinkerVersion), OptionalHeader.MajorLinkerVersion);
	printf("\t%08X\t %02X\t\t Minor Linker Version\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, MinorLinkerVersion), OptionalHeader.MinorLinkerVersion);
	printf("\t%08X\t %08X\t Size of Code\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfCode), OptionalHeader.SizeOfCode);
	printf("\t%08X\t %08X\t Size of Initialized Data\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfInitializedData), OptionalHeader.SizeOfInitializedData);
	printf("\t%08X\t %08X\t Size of Uninitialized Data\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfUninitializedData), OptionalHeader.SizeOfUninitializedData);
	printf("\t%08X\t %08X\t Address of Entry Point\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint), OptionalHeader.AddressOfEntryPoint);
	printf("\t%08X\t %08X\t Base of Code\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, BaseOfCode), OptionalHeader.BaseOfCode);
	printf("\t%08X\t %08X\t Base of Data\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, BaseOfData), OptionalHeader.BaseOfData);
	printf("\t%08X\t %08X\t Image Base\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER, ImageBase), OptionalHeader.ImageBase);
	printf("\t%08X\t %08X\t Section Alignment\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, SectionAlignment), OptionalHeader.SectionAlignment);
	printf("\t%08X\t %08X\t File Alignment\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, FileAlignment), OptionalHeader.FileAlignment);
	printf("\t%08X\t %04X\t\t Major O/S Version\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, MajorOperatingSystemVersion), OptionalHeader.MajorOperatingSystemVersion);
	printf("\t%08X\t %04X\t\t Minor O/S Version\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, MinorOperatingSystemVersion), OptionalHeader.MinorOperatingSystemVersion);
	printf("\t%08X\t %04X\t\t Major Image Version\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, MajorImageVersion), OptionalHeader.MajorImageVersion);
	printf("\t%08X\t %04X\t\t Minor Image Version\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, MinorImageVersion), OptionalHeader.MinorImageVersion);
	printf("\t%08X\t %04X\t\t Major Subsystem Version\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, MajorSubsystemVersion), OptionalHeader.MajorSubsystemVersion);
	printf("\t%08X\t %04X\t\t Minor Subsystem Version\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, MinorSubsystemVersion), OptionalHeader.MinorSubsystemVersion);
	printf("\t%08X\t %08X\t Win32 Version Value\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, Win32VersionValue), OptionalHeader.Win32VersionValue);
	printf("\t%08X\t %08X\t Size of image\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage), OptionalHeader.SizeOfImage);
	printf("\t%08X\t %08X\t Size of Headers\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders), OptionalHeader.SizeOfHeaders);
	printf("\t%08X\t %08X\t Checksum\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum), OptionalHeader.CheckSum);
	printf("\t%08X\t %04X\t\t Subsystem\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, Subsystem), OptionalHeader.Subsystem);
	printf("\t%08X\t %04X\t\t DLL Characteristics\n\n\n", fileoffset + offsetof(IMAGE_OPTIONAL_HEADER32, DllCharacteristics), OptionalHeader.DllCharacteristics);
}

void ShowSectionHeader()
{
	for (int i = 0; i < FileHeader.NumberOfSections; i++)
	{
		printf("\n====================IMAGE_SECTION_HEADER %s====================\n", SectionHeader[i].Name);
		printf("pFile\t\t Data\t\t Description\n");
		printf("%08X\t %2X %2X %2X %2X\t Name\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, Name), SectionHeader[i].Name[0], SectionHeader[i].Name[1], SectionHeader[i].Name[2], SectionHeader[i].Name[3]);
		printf("%08X\t %2X %2X %2X %2X\t\n", SectionOffset + 4 + offsetof(IMAGE_SECTION_HEADER, Name), SectionHeader[i].Name[4], SectionHeader[i].Name[5], SectionHeader[i].Name[6], SectionHeader[i].Name[7]);
		printf("%08X\t %08X\t Virtual Size\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, Misc, VirtualSize), SectionHeader[i].Misc.VirtualSize);
		printf("%08X\t %08X\t RVA\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, VirtualAddress), SectionHeader[i].VirtualAddress);
		printf("%08X\t %08X\t Size of Raw Data\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, SizeOfRawData), SectionHeader[i].SizeOfRawData);
		printf("%08X\t %08X\t Pointer tto Raw Data\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, PointerToRawData), SectionHeader[i].PointerToRawData);
		printf("%08X\t %08X\t Pointer to Relocations\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, PointerToRelocations), SectionHeader[i].PointerToRelocations);
		printf("%08X\t %08X\t Pointer To Line Numbers\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, PointerToLinenumbers), SectionHeader[i].PointerToLinenumbers);
		printf("%08X\t %04X\t\t Number of Relocations\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, NumberOfRelocations), SectionHeader[i].NumberOfRelocations);
		printf("%08X\t %04X\t\t Number of Line Numbers\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, NumberOfLinenumbers), SectionHeader[i].NumberOfLinenumbers);
		printf("%08X\t %08X\t Characteristics\n", SectionOffset + offsetof(IMAGE_SECTION_HEADER, Characteristics), SectionHeader[i].Characteristics);
		SectionOffset = SectionOffset + offsetof(IMAGE_SECTION_HEADER, Characteristics) + 4;
	}

	printf("\n\n");
}