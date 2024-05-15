/*
 * Malware Development for Ethical Hackers
 * hack2.c - Anti-debugging tricks
 * detect debugger via CheckRemoteDebuggerPresent
 * author: @cocomelonc
*/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Function to check if a debugger is present
bool DebuggerCheck() {
  BOOL result;
  CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);
  return result;
}

// Function that simulates the main functionality
void hack() {
  MessageBox(NULL, "Meow!", "=^..^=", MB_OK);
}

int main() {
  // Check if a debugger is present
  if (DebuggerCheck()) {
    MessageBox(NULL, "Bow-wow!", "=^..^=", MB_OK);
    return 1;  // exit if a debugger is present
  }
  // Main functionality
  hack();
  return 0;
}
