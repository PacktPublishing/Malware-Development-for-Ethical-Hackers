/*
 * Malware Development for Ethical Hackers
 * hack.c
 * enum processes and check AV/EDR
 * author: @cocomelonc
*/
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

// define a struct to store process name and description
typedef struct {
  char process_name[256];
  char description[256];
} Process;

// array of Process structs, and counter
Process* process_list;
int process_count = 0;

// read process data from a file
void readProcListFromFile(const char* filename) {
  FILE* file = fopen(filename, "r");
  if (file == NULL) {
    printf("Could not open file %s", filename);
    return;
  }

  char line[512];
  while (fgets(line, sizeof(line), file)) {
    // reallocate memory for each new process
    process_list = (Process*)realloc(process_list, (process_count + 1) * sizeof(Process));
    // parse the line, split it into process name and description
    char* token = strtok(line, "|");
    strcpy(process_list[process_count].process_name, token);
    token = strtok(NULL, "|");
    strcpy(process_list[process_count].description, token);
    process_count++;
  }

  fclose(file);
}

// enumerate running processes
void enumProcs() {
  HANDLE hProcessSnap;
  PROCESSENTRY32 pe32;

  hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap == INVALID_HANDLE_VALUE) {
    printf("CreateToolhelp32Snapshot failed.\n");
    return;
  }

  pe32.dwSize = sizeof(PROCESSENTRY32);

  if (!Process32First(hProcessSnap, &pe32)) {
    printf("Process32First failed.\n");
    CloseHandle(hProcessSnap);
    return;
  }

  do {
    for (int i = 0; i < process_count; i++) {
      if (_stricmp(process_list[i].process_name, pe32.szExeFile) == 0) {
        printf("found process: %s - %s \n", process_list[i].process_name, process_list[i].description);
      }
    }
  } while (Process32Next(hProcessSnap, &pe32));

  CloseHandle(hProcessSnap);
}

int main() {
  readProcListFromFile("processes.txt");
  enumProcs();
  // cleanup allocated memory
  if (process_list) {
    free(process_list);
  }
  return 0;
}