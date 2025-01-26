#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>

// print debugger detected
static void debugger_detected(int signo)
{
    #ifdef DEBUG
    printf("(condi/antidebug) Debugger detected! Exiting...\n");
    #endif
    exit(EXIT_FAILURE);
}

// main function for anti debug
void antidebug(void)
{
    // setup signal
    signal(SIGTRAP, debugger_detected);

    // using ptrace for detected
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
    {
        #ifdef DEBUG
        printf("(condi/antidebug) Debugger detected! Exiting...\n");
        #endif
        exit(EXIT_FAILURE);
    }
}

