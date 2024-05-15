/*
 * Malware Development for Ethical Hackers
 * hack.c - Anti-VM tricks
 * delaying execution
 * author: @cocomelonc
*/
#include <windows.h>
#include <stdio.h>

// Definitions for NtDelayExecution
typedef NTSTATUS (WINAPI *fnNtDelayExecution)(
  BOOLEAN Alertable,
  PLARGE_INTEGER DelayInterval
);

// Function to check if the system is a virtual machine
BOOL checkVM() {
  // Get the system uptime before sleeping
  ULONG64 uptimeBeforeSleep = GetTickCount64();

  // Dynamically obtain the address of NtDelayExecution
  HMODULE ntdll = GetModuleHandle("ntdll.dll");
  fnNtDelayExecution myNtDelayExecution = (fnNtDelayExecution)GetProcAddress(ntdll, "NtDelayExecution");

  // Check if the function is successfully obtained
  if (!myNtDelayExecution) {
    printf("Failed to obtain NtDelayExecution function address.\n");
    return FALSE;
  }

  // Set the sleep time (in 100-nanosecond intervals) - adjust as needed
  LARGE_INTEGER sleepInterval;
  sleepInterval.QuadPart = -10000000; // 1 second

  // Call NtDelayExecution to sleep
  myNtDelayExecution(FALSE, &sleepInterval);

  // Get the system uptime after sleeping
  ULONG64 uptimeAfterSleep = GetTickCount64();

  // Calculate the actual sleep time in milliseconds
  ULONG64 actualSleepTime = uptimeAfterSleep - uptimeBeforeSleep;

  // Print the actual sleep time
  printf("Actual sleep time: %llu milliseconds\n", actualSleepTime);

  // Check if the actual sleep time is close to the expected sleep time
  // This is just a basic example, you might want to adjust the threshold based on your specific use case
  if (actualSleepTime < 1000 && actualSleepTime > 800) {
    printf("Likely not a virtual machine.\n");
  } else {
    printf("Possibly a virtual machine.\n");
  }

  return TRUE;
}

int main() {
  if (checkVM()) {
    // Handle virtual machine detected case
    MessageBox(NULL, "Meow!", "=^..^=", MB_OK);
  } else {
    // Handle non-virtual machine case
    MessageBox(NULL, "Squeak!", "=^..^=", MB_OK);
  }
  return 0;
}
