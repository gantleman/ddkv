/*
Copyright (c) 2009-2011 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/* Please, please, please.

   You are welcome to integrate this code in your favourite Bittorrent
   client.  Please remember, however, that it is meant to be usable by
   others, including myself.  This means no C++, no relicensing, and no
   gratuitious changes to the coding style.  And please send back any
   improvements to the author. */

/* For memmem. */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <list>
#include <map>
#include <vector>
#include <assert.h>

#if !defined(_WIN32) || defined(__MINGW32__)
#include <sys/time.h>
#endif

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#ifndef _WIN32_WINNT
//#define _WIN32_WINNT 0x0501 /* Windows XP */
#endif
#ifndef WINVER
#define WINVER _WIN32_WINNT
#endif
#include <ws2tcpip.h>
#include <windows.h>
#endif
#include "bcode.h"
#include "dht.h"

#ifndef HAVE_MEMMEM
#ifdef __GLIBC__
#define HAVE_MEMMEM
#endif
#endif

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#if !defined(_WIN32) || defined(__MINGW32__)
#define dht_gettimeofday(_ts, _tz) gettimeofday((_ts), (_tz))
#else
extern int dht_gettimeofday(struct timeval *tv, struct timezone *tz);
#endif

#ifdef _WIN32

#undef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT

static int
set_nonblocking(int fd, int nonblocking)
{
	int rc;

	unsigned long mode = !!nonblocking;
	rc = ioctlsocket(fd, FIONBIO, &mode);
	if (rc != 0)
		errno = WSAGetLastError();
	return (rc == 0 ? 0 : -1);
}

static int
random(void)
{
	return rand();
}

/* Windows Vista and later already provide the implementation. */
#if _WIN32_WINNT < 0x0600
extern const char *inet_ntop(int, const void *, char *, socklen_t);
#endif

#ifdef _MSC_VER
/* There is no snprintf in MSVCRT. */
#define snprintf _snprintf
#endif

#else

static int
set_nonblocking(int fd, int nonblocking)
{
	int rc;
	rc = fcntl(fd, F_GETFL, 0);
	if(rc < 0)
		return -1;

	rc = fcntl(fd, F_SETFL, nonblocking?(rc | O_NONBLOCK):(rc & ~O_NONBLOCK));
	if(rc < 0)
		return -1;

	return 0;
}

#endif

/* We set sin_family to 0 to mark unused slots. */
#if AF_INET == 0 || AF_INET6 == 0
#error You lose
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
/* nothing */
#elif defined(__GNUC__)
#define inline __inline
#if  (__GNUC__ >= 3)
#define restrict __restrict
#else
#define restrict /**/
#endif
#else
#define inline /**/
#define restrict /**/
#endif

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

struct node {
	unsigned char id[20];
	struct sockaddr_storage ss;
	int sslen;
	time_t time;                /* time of last message received */
	time_t reply_time;          /* time of last correct reply received */
	time_t pinged_time;         /* time of last request */
	int pinged;                 /* how many requests we sent since last reply */
	struct node *next;
};

struct bucket {
	int af;
	unsigned char first[20];
	int count;                  /* number of nodes */
	time_t time;                /* time of last reply in this bucket */
	struct node *nodes;
	struct sockaddr_storage cached;  /* the address of a likely candidate */
	int cachedlen;
	struct bucket *next;
};

struct search_node {
	unsigned char id[20];
	struct sockaddr_storage ss;
	int sslen;
	time_t request_time;        /* the time of the last unanswered request */
	time_t reply_time;          /* the time of the last reply */
	int pinged;
	unsigned char token[40];
	int token_len;
	int replied;                /* whether we have received a reply */
	int acked;                  /* whether they acked our announcement */
};

/* When performing a search, we search for up to SEARCH_NODES closest nodes
   to the destination, and use the additional ones to backtrack if any of
   the target 8 turn out to be dead. */
#define SEARCH_NODES 14

struct search {
	unsigned short tid;
	int af;
	time_t step_time;           /* the time of the last search_step */
	unsigned char id[20];
	unsigned short port;        /* 0 for pure searches */
	int done;
	struct search_node nodes[SEARCH_NODES];
	int numnodes;
	struct search *next;
};

///Serial broadcast
struct serial_node {
	unsigned char id[20];
	struct sockaddr_storage ss;
	int sslen;
	int pinged;
	unsigned char token[40];
	int token_len;
	int replied;                /* whether we have received a reply */
	int acked;                  /* whether they acked our announcement */
};

struct serial {
	unsigned short tid;
	int af;
	time_t step_time;
	std::list<serial_node> nodes;
	std::vector<char> buf;
	int num;
};

struct peer {
	time_t time;
	unsigned char ip[16];
	unsigned short len;
	unsigned short port;
};
	
/* The maximum number of peers we store for a given hash. */
#ifndef DHT_MAX_PEERS
#define DHT_MAX_PEERS 2048
#endif

/* The maximum number of hashes we're willing to track. */
#ifndef DHT_MAX_HASHES
#define DHT_MAX_HASHES 16384
#endif

/* The maximum number of searches we keep data about. */
#ifndef DHT_MAX_SEARCHES
#define DHT_MAX_SEARCHES 1024
#endif

/* The time after which we consider a search to be expirable. */
#ifndef DHT_SEARCH_EXPIRE_TIME
#define DHT_SEARCH_EXPIRE_TIME (62 * 60)
#endif

struct storage {
	unsigned char id[20];
	int numpeers, maxpeers;
	struct peer *peers;
	struct storage *next;
};

#define ERROR 0
#define REPLY 1
#define PING 2
#define FIND_NODE 3
#define GET_PEERS 4
#define ANNOUNCE_PEER 5

#define WANT4 1
#define WANT6 2

static const unsigned char zeroes[20] = { 0 };
static const unsigned char ones[20] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF
};
static const unsigned char v4prefix[16] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

/* The maximum number of nodes that we snub.  There is probably little
   reason to increase this value. */
#ifndef DHT_MAX_BLACKLISTED
#define DHT_MAX_BLACKLISTED 10
#endif

#define MAX_TOKEN_BUCKET_TOKENS 400

typedef struct _dht
{
	int dht_socket;
	int dht_socket6;

	time_t search_time;
	time_t confirm_nodes_time;
	time_t rotate_secrets_time;

	unsigned char myid[20];
	int have_v;
	unsigned char my_v[9];
	unsigned char secret[8];
	unsigned char oldsecret[8];

	struct bucket *buckets;
	struct bucket *buckets6;
	struct storage *storage;
	int numstorage;

	struct search *searches;
	int numsearches;
	unsigned short search_id;

	struct sockaddr_storage blacklist[DHT_MAX_BLACKLISTED];
	int next_blacklisted;

	struct timeval now;
	time_t mybucket_grow_time, mybucket6_grow_time;
	time_t expire_stuff_time;

	time_t token_bucket_time;
	int token_bucket_tokens;

	FILE *dht_debug;

	std::map<int, serial> seriales;
}*pdht, dht;

static struct storage * find_storage(pdht D, const unsigned char *id);
static void flush_search_node(struct search_node *n, struct search *sr);

static int send_ping(pdht D, const struct sockaddr *sa, int salen,
	const unsigned char *tid, int tid_len);
static int send_pong(pdht D, const struct sockaddr *sa, int salen,
	const unsigned char *tid, int tid_len);
static int send_find_node(pdht D, const struct sockaddr *sa, int salen,
	const unsigned char *tid, int tid_len,
	const unsigned char *target, int want, int confirm);
static int send_nodes_peers(pdht D, const struct sockaddr *sa, int salen,
	const unsigned char *tid, int tid_len,
	const unsigned char *nodes, int nodes_len,
	const unsigned char *nodes6, int nodes6_len,
	int af, struct storage *st,
	const unsigned char *token, int token_len);
static int send_closest_nodes(pdht D, const struct sockaddr *sa, int salen,
	const unsigned char *tid, int tid_len,
	const unsigned char *id, int want,
	int af, struct storage *st,
	const unsigned char *token, int token_len);
static int send_get_peers(pdht D, const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len,
	unsigned char *infohash, int want, int confirm);
static int send_announce_peer(pdht D, const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len,
	unsigned char *infohas, unsigned short port,
	unsigned char *token, int token_len, int confirm);
static int send_peer_announced(pdht D, const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len);
static int send_error(pdht D, const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len,
	int code, const char *message);
static void process_message(pdht D, const unsigned char *buf, int buflen,
	const struct sockaddr *from, int fromlen,
	dht_callback *callback, void *closure
	);

#ifdef __GNUC__
__attribute__ ((format (printf, 1, 2)))
#endif
static void
debugf(pdht D, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	if (D->dht_debug)
		vfprintf(D->dht_debug, format, args);
	va_end(args);
	if (D->dht_debug)
		fflush(D->dht_debug);
}

static void
debug_printable(pdht D, const unsigned char *buf, int buflen)
{
	int i;
	if (D->dht_debug) {
		for (i = 0; i < buflen; i++)
			putc(buf[i] >= 32 && buf[i] <= 126 ? buf[i] : '.', D->dht_debug);
	}
}

static
void debugf_hex(pdht D, const char* head, const unsigned char *buf, int buflen)
{
	if (!D->dht_debug)
		return;
	fprintf(D->dht_debug, head);

	int i;
	for (i = 0; i < buflen; i++)
		fprintf(D->dht_debug, "%02x", buf[i]);

	fprintf(D->dht_debug, "\n");
	fflush(D->dht_debug);
}

static
void print_hex(FILE *f, const unsigned char *buf, int buflen)
{
	int i;
	for (i = 0; i < buflen; i++)
		fprintf(f, "%02x", buf[i]);
}

static int
is_martian(pdht D, const struct sockaddr *sa)
{
	if (D->dht_debug != NULL)
		return 0;

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		const unsigned char *address = (const unsigned char*)&sin->sin_addr;
		return sin->sin_port == 0 ||
			(address[0] == 0) ||
			(address[0] == 127) ||
			((address[0] & 0xE0) == 0xE0);
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		const unsigned char *address = (const unsigned char*)&sin6->sin6_addr;
		return sin6->sin6_port == 0 ||
			(address[0] == 0xFF) ||
			(address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
			(memcmp(address, zeroes, 15) == 0 &&
			(address[15] == 0 || address[15] == 1)) ||
			(memcmp(address, v4prefix, 12) == 0);
	}

	default:
		return 0;
	}
}

/* Forget about the ``XOR-metric''.  An id is just a path from the
   root of the tree, so bits are numbered from the start. */

static int
id_cmp(const unsigned char *restrict id1, const unsigned char *restrict id2)
{
	/* Memcmp is guaranteed to perform an unsigned comparison. */
	return memcmp(id1, id2, 20);
}

/* Find the lowest 1 bit in an id. */
static int
lowbit(const unsigned char *id)
{
	int i, j;
	for (i = 19; i >= 0; i--)
		if (id[i] != 0)
			break;

	if (i < 0)
		return -1;

	for (j = 7; j >= 0; j--)
		if ((id[i] & (0x80 >> j)) != 0)
			break;

	return 8 * i + j;
}

/* Find how many bits two ids have in common. */
static int
common_bits(const unsigned char *id1, const unsigned char *id2)
{
	int i, j;
	unsigned char xor;
	for (i = 0; i < 20; i++) {
		if (id1[i] != id2[i])
			break;
	}

	if (i == 20)
		return 160;

	xor = id1[i] ^ id2[i];

	j = 0;
	while ((xor & 0x80) == 0) {
		xor <<= 1;
		j++;
	}

	return 8 * i + j;
}

/* Determine whether id1 or id2 is closer to ref */
static int
xorcmp(const unsigned char *id1, const unsigned char *id2,
const unsigned char *ref)
{
	int i;
	for (i = 0; i < 20; i++) {
		unsigned char xor1, xor2;
		if (id1[i] == id2[i])
			continue;
		xor1 = id1[i] ^ ref[i];
		xor2 = id2[i] ^ ref[i];
		if (xor1 < xor2)
			return -1;
		else
			return 1;
	}
	return 0;
}

/* We keep buckets in a sorted linked list.  A bucket b ranges from
   b->first inclusive up to b->next->first exclusive. */
static int
in_bucket(const unsigned char *id, struct bucket *b)
{
	return id_cmp(b->first, id) <= 0 &&
		(b->next == NULL || id_cmp(id, b->next->first) < 0);
}

static struct bucket *
find_bucket(pdht D, unsigned const char *id, int af)
{
	struct bucket *b = af == AF_INET ? D->buckets : D->buckets6;

	if (b == NULL)
		return NULL;

	while (1) {
		if (b->next == NULL)
			return b;
		if (id_cmp(id, b->next->first) < 0)
			return b;
		b = b->next;
	}
}

static struct bucket *
previous_bucket(pdht D, struct bucket *b)
{
	struct bucket *p = b->af == AF_INET ? D->buckets : D->buckets6;

	if (b == p)
		return NULL;

	while (1) {
		if (p->next == NULL)
			return NULL;
		if (p->next == b)
			return p;
		p = p->next;
	}
}

/* Every bucket contains an unordered list of nodes. */
static struct node *
find_node(pdht D, const unsigned char *id, int af)
{
	struct bucket *b = find_bucket(D, id, af);
	struct node *n;

	if (b == NULL)
		return NULL;

	n = b->nodes;
	while (n) {
		if (id_cmp(n->id, id) == 0)
			return n;
		n = n->next;
	}
	return NULL;
}

/* Return a random node in a bucket. */
static struct node *
random_node(struct bucket *b)
{
	struct node *n;
	int nn;

	if (b->count == 0)
		return NULL;

	nn = random() % b->count;
	n = b->nodes;
	while (nn > 0 && n) {
		n = n->next;
		nn--;
	}
	return n;
}

/* Return the middle id of a bucket. */
static int
bucket_middle(struct bucket *b, unsigned char *id_return)
{
	int bit1 = lowbit(b->first);
	int bit2 = b->next ? lowbit(b->next->first) : -1;
	int bit = MAX(bit1, bit2) + 1;

	if (bit >= 160)
		return -1;

	memcpy(id_return, b->first, 20);
	id_return[bit / 8] |= (0x80 >> (bit % 8));
	return 1;
}

/* Return a random id within a bucket. */
static int
bucket_random(struct bucket *b, unsigned char *id_return)
{
	int bit1 = lowbit(b->first);
	int bit2 = b->next ? lowbit(b->next->first) : -1;
	int bit = MAX(bit1, bit2) + 1;
	int i;

	if (bit >= 160) {
		memcpy(id_return, b->first, 20);
		return 1;
	}

	memcpy(id_return, b->first, bit / 8);
	id_return[bit / 8] = b->first[bit / 8] & (0xFF00 >> (bit % 8));
	id_return[bit / 8] |= random() & 0xFF >> (bit % 8);
	for (i = bit / 8 + 1; i < 20; i++)
		id_return[i] = random() & 0xFF;
	return 1;
}

/* Insert a new node into a bucket. */
static struct node *
insert_node(pdht D, struct node *node)
{
	struct bucket *b = find_bucket(D, node->id, node->ss.ss_family);

	if (b == NULL)
		return NULL;

	node->next = b->nodes;
	b->nodes = node;
	b->count++;
	return node;
}

/* This is our definition of a known-good node. */
static int
node_good(pdht D, struct node *node)
{
	return
		node->pinged <= 2 &&
		node->reply_time >= D->now.tv_sec - 7200 &&
		node->time >= D->now.tv_sec - 900;
}

/* Our transaction-ids are 4-bytes long, with the first two bytes identi-
   fying the kind of request, and the remaining two a sequence number in
   host order. */

static void
make_tid(unsigned char *tid_return, const char *prefix, unsigned short seqno)
{
	tid_return[0] = prefix[0] & 0xFF;
	tid_return[1] = prefix[1] & 0xFF;
	memcpy(tid_return + 2, &seqno, 2);
}

static int
tid_match(const unsigned char *tid, const char *prefix,
unsigned short *seqno_return)
{
	if (tid[0] == (prefix[0] & 0xFF) && tid[1] == (prefix[1] & 0xFF)) {
		if (seqno_return)
			memcpy(seqno_return, tid + 2, 2);
		return 1;
	}
	else
		return 0;
}

/* Every bucket caches the address of a likely node.  Ping it. */
static int
send_cached_ping(pdht D, struct bucket *b)
{
	unsigned char tid[4];
	int rc;
	/* We set family to 0 when there's no cached node. */
	if (b->cached.ss_family == 0)
		return 0;

	debugf(D, "Sending ping to cached node.\n");
	make_tid(tid, "pn", 0);
	rc = send_ping(D, (struct sockaddr*)&b->cached, b->cachedlen, tid, 4);
	b->cached.ss_family = 0;
	b->cachedlen = 0;
	return rc;
}

/* Called whenever we send a request to a node, increases the ping count
   and, if that reaches 3, sends a ping to a new candidate. */
static void 
pinged(pdht D, struct node *n, struct bucket *b)
{
	n->pinged++;
	n->pinged_time = D->now.tv_sec;
	if (n->pinged >= 3)
		send_cached_ping(D, b ? b : find_bucket(D, n->id, n->ss.ss_family));
}

/* The internal blacklist is an LRU cache of nodes that have sent
   incorrect messages. */
static void
blacklist_node(pdht D, const unsigned char *id, const struct sockaddr *sa, int salen)
{
	int i;

	debugf(D, "Blacklisting broken node.\n");

	if (id) {
		struct node *n;
		struct search *sr;
		/* Make the node easy to discard. */
		n = find_node(D, id, sa->sa_family);
		if (n) {
			n->pinged = 3;
			pinged(D, n, NULL);
		}
		/* Discard it from any searches in progress. */
		sr = D->searches;
		while (sr) {
			for (i = 0; i < sr->numnodes; i++)
				if (id_cmp(sr->nodes[i].id, id) == 0)
					flush_search_node(&sr->nodes[i], sr);
			sr = sr->next;
		}
	}
	/* And make sure we don't hear from it again. */
	memcpy(&D->blacklist[D->next_blacklisted], sa, salen);
	D->next_blacklisted = (D->next_blacklisted + 1) % DHT_MAX_BLACKLISTED;
}

static int
node_blacklisted(pdht D, const struct sockaddr *sa, int salen)
{
	int i;

	if ((unsigned)salen > sizeof(struct sockaddr_storage))
		abort();

	if (dht_blacklisted(sa, salen))
		return 1;

	for (i = 0; i < DHT_MAX_BLACKLISTED; i++) {
		if (memcmp(&D->blacklist[i], sa, salen) == 0)
			return 1;
	}

	return 0;
}

/* Split a bucket into two equal parts. */
static struct bucket *
split_bucket(pdht D, struct bucket *b)
{
	struct bucket *newb;
	struct node *nodes;
	int rc;
	unsigned char new_id[20];

	rc = bucket_middle(b, new_id);
	if (rc < 0)
		return NULL;

	newb = (bucket *)calloc(1, sizeof(struct bucket));
	if (newb == NULL)
		return NULL;

	newb->af = b->af;

	send_cached_ping(D, b);

	memcpy(newb->first, new_id, 20);
	newb->time = b->time;

	nodes = b->nodes;
	b->nodes = NULL;
	b->count = 0;
	newb->next = b->next;
	b->next = newb;
	while (nodes) {
		struct node *n;
		n = nodes;
		nodes = nodes->next;
		insert_node(D, n);
	}
	return b;
}

/* We just learnt about a node, not necessarily a new one.  Confirm is 1 if
   the node sent a message, 2 if it sent us a reply. */
static struct node *
new_node(pdht D, const unsigned char *id, const struct sockaddr *sa, int salen,
int confirm)
{
	struct bucket *b = find_bucket(D, id, sa->sa_family);
	struct node *n;
	int mybucket, split;

	if (b == NULL)
		return NULL;

	if (id_cmp(id, D->myid) == 0)
		return NULL;

	if (is_martian(D, sa) || node_blacklisted(D, sa, salen))
		return NULL;

	mybucket = in_bucket(D->myid, b);

	if (confirm == 2)
		b->time = D->now.tv_sec;

	n = b->nodes;
	while (n) {
		if (id_cmp(n->id, id) == 0) {
			if (confirm || n->time < D->now.tv_sec - 15 * 60) {
				/* Known node.  Update stuff. */
				memcpy((struct sockaddr*)&n->ss, sa, salen);
				if (confirm)
					n->time = D->now.tv_sec;
				if (confirm >= 2) {
					n->reply_time = D->now.tv_sec;
					n->pinged = 0;
					n->pinged_time = 0;
				}
			}
			return n;
		}
		n = n->next;
	}

	/* New node. */

	if (mybucket) {
		if (sa->sa_family == AF_INET)
			D->mybucket_grow_time = D->now.tv_sec;
		else
			D->mybucket6_grow_time = D->now.tv_sec;
	}

	/* First, try to get rid of a known-bad node. */
	n = b->nodes;
	while (n) {
		if (n->pinged >= 3 && n->pinged_time < D->now.tv_sec - 15) {
			memcpy(n->id, id, 20);
			memcpy((struct sockaddr*)&n->ss, sa, salen);
			n->time = confirm ? D->now.tv_sec : 0;
			n->reply_time = confirm >= 2 ? D->now.tv_sec : 0;
			n->pinged_time = 0;
			n->pinged = 0;
			return n;
		}
		n = n->next;
	}

	if (b->count >= 8) {
		/* Bucket full.  Ping a dubious node */
		int dubious = 0;
		n = b->nodes;
		while (n) {
			/* Pick the first dubious node that we haven't pinged in the
			   last 15 seconds.  This gives nodes the time to reply, but
			   tends to concentrate on the same nodes, so that we get rid
			   of bad nodes fast. */
			if (!node_good(D, n)) {
				dubious = 1;
				if (n->pinged_time < D->now.tv_sec - 15) {
					unsigned char tid[4];
					debugf(D, "Sending ping to dubious node.\n");
					make_tid(tid, "pn", 0);
					send_ping(D, (struct sockaddr*)&n->ss, n->sslen,
						tid, 4);
					n->pinged++;
					n->pinged_time = D->now.tv_sec;
					break;
				}
			}
			n = n->next;
		}

		split = 0;
		if (mybucket) {
			if (!dubious)
				split = 1;
			/* If there's only one bucket, split eagerly.  This is
			   incorrect unless there's more than 8 nodes in the DHT. */
			else if (b->af == AF_INET && D->buckets->next == NULL)
				split = 1;
			else if (b->af == AF_INET6 && D->buckets6->next == NULL)
				split = 1;
		}

		if (split) {
			debugf(D, "Splitting.\n");
			b = split_bucket(D, b);
			return new_node(D, id, sa, salen, confirm);
		}

		/* No space for this node.  Cache it away for later. */
		if (confirm || b->cached.ss_family == 0) {
			memcpy(&b->cached, sa, salen);
			b->cachedlen = salen;
		}

		return NULL;
	}

	/* Create a new node. */
	n = (node *)calloc(1, sizeof(struct node));
	if (n == NULL)
		return NULL;
	memcpy(n->id, id, 20);
	memcpy(&n->ss, sa, salen);
	n->sslen = salen;
	n->time = confirm ? D->now.tv_sec : 0;
	n->reply_time = confirm >= 2 ? D->now.tv_sec : 0;
	n->next = b->nodes;
	b->nodes = n;
	b->count++;
	return n;
}

/* Called periodically to purge known-bad nodes.  Note that we're very
   conservative here: broken nodes in the table don't do much harm, we'll
   recover as soon as we find better ones. */
static int
expire_buckets(pdht D, struct bucket *b)
{
	while (b) {
		struct node *n, *p;
		int changed = 0;

		while (b->nodes && b->nodes->pinged >= 4) {
			n = b->nodes;
			b->nodes = n->next;
			b->count--;
			changed = 1;
			free(n);
		}

		p = b->nodes;
		while (p) {
			while (p->next && p->next->pinged >= 4) {
				n = p->next;
				p->next = n->next;
				b->count--;
				changed = 1;
				free(n);
			}
			p = p->next;
		}

		if (changed)
			send_cached_ping(D, b);

		b = b->next;
	}
	D->expire_stuff_time = D->now.tv_sec + 120 + random() % 240;
	return 1;
}

/* While a search is in progress, we don't necessarily keep the nodes being
   walked in the main bucket table.  A search in progress is identified by
   a unique transaction id, a short (and hence small enough to fit in the
   transaction id of the protocol packets). */

static struct search *
find_search(pdht D, unsigned short tid, int af)
{
	struct search *sr = D->searches;
	while (sr) {
		if (sr->tid == tid && sr->af == af)
			return sr;
		sr = sr->next;
	}
	return NULL;
}

/* A search contains a list of nodes, sorted by decreasing distance to the
   target.  We just got a new candidate, insert it at the right spot or
   discard it. */

static int
insert_search_node(pdht D, unsigned char *id,
const struct sockaddr *sa, int salen,
struct search *sr, int replied,
	unsigned char *token, int token_len)
{
	struct search_node *n;
	int i, j;

	if (sa->sa_family != sr->af) {
		debugf(D, "Attempted to insert node in the wrong family.\n");
		return 0;
	}

	for (i = 0; i < sr->numnodes; i++) {
		if (id_cmp(id, sr->nodes[i].id) == 0) {
			n = &sr->nodes[i];
			goto found;
		}
		if (xorcmp(id, sr->nodes[i].id, sr->id) < 0)
			break;
	}

	if (i == SEARCH_NODES)
		return 0;

	if (sr->numnodes < SEARCH_NODES)
		sr->numnodes++;

	for (j = sr->numnodes - 1; j > i; j--) {
		sr->nodes[j] = sr->nodes[j - 1];
	}

	n = &sr->nodes[i];

	memset(n, 0, sizeof(struct search_node));
	memcpy(n->id, id, 20);

found:
	memcpy(&n->ss, sa, salen);
	n->sslen = salen;

	if (replied) {
		n->replied = 1;
		n->reply_time = D->now.tv_sec;
		n->request_time = 0;
		n->pinged = 0;
	}
	if (token) {
		if (token_len >= 40) {
			debugf(D, "Eek!  Overlong token.\n");
		}
		else {
			memcpy(n->token, token, token_len);
			n->token_len = token_len;
		}
	}

	return 1;
}

static void
flush_search_node(struct search_node *n, struct search *sr)
{
	int i = n - sr->nodes, j;
	for (j = i; j < sr->numnodes - 1; j++)
		sr->nodes[j] = sr->nodes[j + 1];
	sr->numnodes--;
}

static void
expire_searches(pdht D)
{
	struct search *sr = D->searches, *previous = NULL;

	while (sr) {
		struct search *next = sr->next;
		if (sr->step_time < D->now.tv_sec - DHT_SEARCH_EXPIRE_TIME) {
			if (previous)
				previous->next = next;
			else
				D->searches = next;
			free(sr);
			D->numsearches--;
		}
		else {
			previous = sr;
		}
		sr = next;
	}
}

/* This must always return 0 or 1, never -1, not even on failure (see below). */
static int
search_send_get_peers(pdht D, struct search *sr, struct search_node *n)
{
	struct node *node;
	unsigned char tid[4];

	if (n == NULL) {
		int i;
		for (i = 0; i < sr->numnodes; i++) {
			if (sr->nodes[i].pinged < 3 && !sr->nodes[i].replied &&
				sr->nodes[i].request_time < D->now.tv_sec - 15)
				n = &sr->nodes[i];
		}
	}

	if (!n || n->pinged >= 3 || n->replied ||
		n->request_time >= D->now.tv_sec - 15)
		return 0;

	debugf(D, "Sending get_peers.\n");
	make_tid(tid, "gp", sr->tid);
	debugf_hex(D, "tid:", tid, 4);
	send_get_peers(D, (struct sockaddr*)&n->ss, n->sslen, tid, 4, sr->id, -1,
		n->reply_time >= D->now.tv_sec - 15);
	n->pinged++;
	n->request_time = D->now.tv_sec;
	/* If the node happens to be in our main routing table, mark it
	   as pinged. */
	node = find_node(D, n->id, n->ss.ss_family);
	if (node) pinged(D, node, NULL);
	return 1;
}

/* When a search is in progress, we periodically call search_step to send
   further requests. */
static void
search_step(pdht D, struct search *sr, dht_callback *callback, void *closure)
{
	int i, j;
	int all_done = 1;

	/* Check if the first 8 live nodes have replied. */
	j = 0;
	for (i = 0; i < sr->numnodes && j < 8; i++) {
		struct search_node *n = &sr->nodes[i];
		if (n->pinged >= 3)
			continue;
		if (!n->replied) {
			all_done = 0;
			break;
		}
		j++;
	}

	if (all_done) {
		if (sr->port == 0) {
			goto done;
		}
		else {
			int all_acked = 1;
			j = 0;
			for (i = 0; i < sr->numnodes && j < 8; i++) {
				struct search_node *n = &sr->nodes[i];
				struct node *node;
				unsigned char tid[4];
				if (n->pinged >= 3)
					continue;
				/* A proposed extension to the protocol consists in
				   omitting the token when storage tables are full.  While
				   I don't think this makes a lot of sense -- just sending
				   a positive reply is just as good --, let's deal with it. */
				if (n->token_len == 0)
					n->acked = 1;
				if (!n->acked) {
					all_acked = 0;
					debugf(D, "Sending announce_peer.\n");
					make_tid(tid, "ap", sr->tid);
					send_announce_peer(D, (struct sockaddr*)&n->ss,
						sizeof(struct sockaddr_storage),
						tid, 4, sr->id, sr->port,
						n->token, n->token_len,
						n->reply_time >= D->now.tv_sec - 15);
					n->pinged++;
					n->request_time = D->now.tv_sec;
					node = find_node(D, n->id, n->ss.ss_family);
					if (node) pinged(D, node, NULL);
				}
				j++;
			}
			if (all_acked)
				goto done;
		}
		sr->step_time = D->now.tv_sec;
		return;
	}

	if (sr->step_time + 15 >= D->now.tv_sec)
		return;
	
	j = 0;
	for (i = 0; i < sr->numnodes; i++) {
		j += search_send_get_peers(D, sr, &sr->nodes[i]);
		if (j >= 3)
			break;
	}
	sr->step_time = D->now.tv_sec;
	return;

done:
	sr->done = 1;
	if (callback)
		(*callback)((DHT)D, closure,
		sr->af == AF_INET ?
	DHT_EVENT_SEARCH_DONE : DHT_EVENT_SEARCH_DONE6,
							sr->id, NULL, 0);
	sr->step_time = D->now.tv_sec;
}

static struct search *
new_search(pdht D)
{
	struct search *sr, *oldest = NULL;

	/* Find the oldest done search */
	sr = D->searches;
	while (sr) {
		if (sr->done &&
			(oldest == NULL || oldest->step_time > sr->step_time))
			oldest = sr;
		sr = sr->next;
	}

	/* The oldest slot is expired. */
	if (oldest && oldest->step_time < D->now.tv_sec - DHT_SEARCH_EXPIRE_TIME)
		return oldest;

	/* Allocate a new slot. */
	if (D->numsearches < DHT_MAX_SEARCHES) {
		sr = (search *)calloc(1, sizeof(struct search));
		if (sr != NULL) {
			sr->next = D->searches;
			D->searches = sr;
			D->numsearches++;
			return sr;
		}
	}

	/* Oh, well, never mind.  Reuse the oldest slot. */
	return oldest;
}

/* Insert the contents of a bucket into a search structure. */
static void
insert_search_bucket(pdht D, struct bucket *b, struct search *sr)
{
	struct node *n;
	n = b->nodes;
	while (n) {
		insert_search_node(D, n->id, (struct sockaddr*)&n->ss, n->sslen,
			sr, 0, NULL, 0);
		n = n->next;
	}
}

/* Start a search.  If port is non-zero, perform an announce when the
   search is complete. */
int
dht_search(DHT iD, const unsigned char *id, int port, int af,
dht_callback *callback, void *closure)
{
	pdht D = (pdht)iD;

	struct search *sr;
	struct storage *st;
	struct bucket *b = find_bucket(D, id, af);

	if (b == NULL) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	/* Try to answer this search locally.  In a fully grown DHT this
	   is very unlikely, but people are running modified versions of
	   this code in private DHTs with very few nodes.  What's wrong
	   with flooding? */
	if (callback) {
		st = find_storage(D, id);
		if (st) {
			unsigned short swapped;
			unsigned char buf[18];
			int i;

			debugf(D, "Found local data (%d peers).\n", st->numpeers);

			for (i = 0; i < st->numpeers; i++) {
				swapped = htons(st->peers[i].port);
				if (st->peers[i].len == 4) {
					memcpy(buf, st->peers[i].ip, 4);
					memcpy(buf + 4, &swapped, 2);
					(*callback)((DHT)D, closure, DHT_EVENT_VALUES, id,
						(void*)buf, 6);
				}
				else if (st->peers[i].len == 16) {
					memcpy(buf, st->peers[i].ip, 16);
					memcpy(buf + 16, &swapped, 2);
					(*callback)((DHT)D, closure, DHT_EVENT_VALUES6, id,
						(void*)buf, 18);
				}
			}
		}
	}

	sr = D->searches;
	while (sr) {
		if (sr->af == af && id_cmp(sr->id, id) == 0)
			break;
		sr = sr->next;
	}

	if (sr) {
		if (sr->done)
		{
			/* We're reusing data from an old search.  Reusing the same tid
				means that we can merge replies for both searches. */
			int i;
			sr->done = 0;
			sr->step_time = 0;
		again:
			for (i = 0; i < sr->numnodes; i++) {
				struct search_node *n;
				n = &sr->nodes[i];
				/* Discard any doubtful nodes. */
				if (n->pinged >= 3 || n->reply_time < D->now.tv_sec - 7200) {
					flush_search_node(n, sr);
					goto again;
				}
				n->pinged = 0;
				n->token_len = 0;
				n->replied = 0;
				n->acked = 0;		
			}
		}
		else
			return -1;///Reject other requests in searching
	}
	else {
		sr = new_search(D);
		if (sr == NULL) {
			errno = ENOSPC;
			return -1;
		}
		sr->af = af;
		sr->tid = D->search_id++;
		sr->step_time = 0;
		memcpy(sr->id, id, 20);
		sr->done = 0;
		sr->numnodes = 0;
	}

	sr->port = port;

	insert_search_bucket(D, b, sr);

	if (sr->numnodes < SEARCH_NODES) {
		struct bucket *p = previous_bucket(D, b);
		if (b->next)
			insert_search_bucket(D, b->next, sr);
		if (p)
			insert_search_bucket(D, p, sr);
	}
	if (sr->numnodes < SEARCH_NODES)
		insert_search_bucket(D, find_bucket(D, D->myid, af), sr);

	search_step(D, sr, callback, closure);
	D->search_time = D->now.tv_sec;
	return 1;
}

/* A struct storage stores all the stored peer addresses for a given info
   hash. */

static struct storage *
find_storage(pdht D, const unsigned char *id)
{
	struct storage *st = D->storage;

	while (st) {
		if (id_cmp(id, st->id) == 0)
			break;
		st = st->next;
	}
	return st;
}

static int
storage_store(pdht D, const unsigned char *id,
const struct sockaddr *sa, unsigned short port)
{
	int i, len;
	struct storage *st;
	unsigned char *ip;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		ip = (unsigned char*)&sin->sin_addr;
		len = 4;
	}
	else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		ip = (unsigned char*)&sin6->sin6_addr;
		len = 16;
	}
	else {
		return -1;
	}

	st = find_storage(D, id);

	if (st == NULL) {
		if (D->numstorage >= DHT_MAX_HASHES)
			return -1;
		st = (storage *)calloc(1, sizeof(struct storage));
		if (st == NULL) return -1;
		memcpy(st->id, id, 20);
		st->next = D->storage;
		D->storage = st;
		D->numstorage++;
	}

	for (i = 0; i < st->numpeers; i++) {
		if (st->peers[i].port == port && st->peers[i].len == len &&
			memcmp(st->peers[i].ip, ip, len) == 0)
			break;
	}

	if (i < st->numpeers) {
		/* Already there, only need to refresh */
		st->peers[i].time = D->now.tv_sec;
		return 0;
	}
	else {
		struct peer *p;
		if (i >= st->maxpeers) {
			/* Need to expand the array. */
			struct peer *new_peers;
			int n;
			if (st->maxpeers >= DHT_MAX_PEERS)
				return 0;
			n = st->maxpeers == 0 ? 2 : 2 * st->maxpeers;
			n = MIN(n, DHT_MAX_PEERS);
			new_peers = (peer *)realloc(st->peers, n * sizeof(struct peer));
			if (new_peers == NULL)
				return -1;
			st->peers = new_peers;
			st->maxpeers = n;
		}
		p = &st->peers[st->numpeers++];
		p->time = D->now.tv_sec;
		p->len = len;
		memcpy(p->ip, ip, len);
		p->port = port;
		return 1;
	}
}

static int
expire_storage(pdht D)
{
	struct storage *st = D->storage, *previous = NULL;
	while (st) {
		int i = 0;
		while (i < st->numpeers) {
			if (st->peers[i].time < D->now.tv_sec - 32 * 60) {
				if (i != st->numpeers - 1)
					st->peers[i] = st->peers[st->numpeers - 1];
				st->numpeers--;
			}
			else {
				i++;
			}
		}

		if (st->numpeers == 0) {
			free(st->peers);
			if (previous)
				previous->next = st->next;
			else
				D->storage = st->next;
			free(st);
			if (previous)
				st = previous->next;
			else
				st = D->storage;
			D->numstorage--;
			if (D->numstorage < 0) {
				debugf(D, "Eek... numstorage became negative.\n");
				D->numstorage = 0;
			}
		}
		else {
			previous = st;
			st = st->next;
		}
	}
	return 1;
}

static int
rotate_secrets(pdht D)
{
	int rc;

	D->rotate_secrets_time = D->now.tv_sec + 900 + random() % 1800;

	memcpy(D->oldsecret, D->secret, sizeof(D->secret));
	rc = dht_random_bytes(D->secret, sizeof(D->secret));

	if (rc < 0)
		return -1;

	return 1;
}

#ifndef TOKEN_SIZE
#define TOKEN_SIZE 8
#endif

static void
make_token(pdht D, const struct sockaddr *sa, int old, unsigned char *token_return)
{
	void *ip;
	int iplen;
	unsigned short port;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)sa;
		ip = &sin->sin_addr;
		iplen = 4;
		port = htons(sin->sin_port);
	}
	else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		ip = &sin6->sin6_addr;
		iplen = 16;
		port = htons(sin6->sin6_port);
	}
	else {
		abort();
	}

	dht_hash(token_return, TOKEN_SIZE,
		old ? D->oldsecret : D->secret, sizeof(D->secret),
		ip, iplen, (unsigned char*)&port, 2);
}
static int
token_match(pdht D, const unsigned char *token, int token_len,
const struct sockaddr *sa)
{
	unsigned char t[TOKEN_SIZE];
	if (token_len != TOKEN_SIZE)
		return 0;
	make_token(D, sa, 0, t);
	if (memcmp(t, token, TOKEN_SIZE) == 0)
		return 1;
	make_token(D, sa, 1, t);
	if (memcmp(t, token, TOKEN_SIZE) == 0)
		return 1;
	return 0;
}

int
dht_nodes(DHT iD, int af, int *good_return, int *dubious_return, int *cached_return,
int *incoming_return)
{
	pdht D = (pdht)iD;

	int good = 0, dubious = 0, cached = 0, incoming = 0;
	struct bucket *b = af == AF_INET ? D->buckets : D->buckets6;

	while (b) {
		struct node *n = b->nodes;
		while (n) {
			if (node_good(D, n)) {
				good++;
				if (n->time > n->reply_time)
					incoming++;
			}
			else {
				dubious++;
			}
			n = n->next;
		}
		if (b->cached.ss_family > 0)
			cached++;
		b = b->next;
	}
	if (good_return)
		*good_return = good;
	if (dubious_return)
		*dubious_return = dubious;
	if (cached_return)
		*cached_return = cached;
	if (incoming_return)
		*incoming_return = incoming;
	return good + dubious;
}

static void
dump_bucket(pdht D, FILE *f, struct bucket *b)
{
	struct node *n = b->nodes;
	fprintf(f, "Bucket ");
	print_hex(f, b->first, 20);
	fprintf(f, " count %d age %d%s%s:\n",
		b->count, (int)(D->now.tv_sec - b->time),
		in_bucket(D->myid, b) ? " (mine)" : "",
		b->cached.ss_family ? " (cached)" : "");
	while (n) {
		char buf[512];
		unsigned short port;
		fprintf(f, "    Node ");
		print_hex(f, n->id, 20);
		if (n->ss.ss_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in*)&n->ss;
			inet_ntop(AF_INET, &sin->sin_addr, buf, 512);
			port = ntohs(sin->sin_port);
		}
		else if (n->ss.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
			inet_ntop(AF_INET6, &sin6->sin6_addr, buf, 512);
			port = ntohs(sin6->sin6_port);
		}
		else {
			snprintf(buf, 512, "unknown(%d)", n->ss.ss_family);
			port = 0;
		}

		if (n->ss.ss_family == AF_INET6)
			fprintf(f, " [%s]:%d ", buf, port);
		else
			fprintf(f, " %s:%d ", buf, port);
		if (n->time != n->reply_time)
			fprintf(f, "age %ld, %ld",
			(long)(D->now.tv_sec - n->time),
			(long)(D->now.tv_sec - n->reply_time));
		else
			fprintf(f, "age %ld", (long)(D->now.tv_sec - n->time));
		if (n->pinged)
			fprintf(f, " (%d)", n->pinged);
		if (node_good(D, n))
			fprintf(f, " (good)");
		fprintf(f, "\n");
		n = n->next;
	}

}

void
dht_dump_tables(DHT iD, FILE *f)
{
	pdht D = (pdht)iD;

	int i;
	struct bucket *b;
	struct storage *st = D->storage;
	struct search *sr = D->searches;

	fprintf(f, "My id ");
	print_hex(f, D->myid, 20);
	fprintf(f, "\n");

	b = D->buckets;
	while (b) {
		dump_bucket(D, f, b);
		b = b->next;
	}

	fprintf(f, "\n");

	b = D->buckets6;
	while (b) {
		dump_bucket(D, f, b);
		b = b->next;
	}

	while (sr) {
		fprintf(f, "\nSearch%s id ", sr->af == AF_INET6 ? " (IPv6)" : "");
		print_hex(f, sr->id, 20);
		fprintf(f, " age %d%s\n", (int)(D->now.tv_sec - sr->step_time),
			sr->done ? " (done)" : "");
		for (i = 0; i < sr->numnodes; i++) {
			struct search_node *n = &sr->nodes[i];
			fprintf(f, "Node %d id ", i);
			print_hex(f, n->id, 20);
			fprintf(f, " bits %d age ", common_bits(sr->id, n->id));
			if (n->request_time)
				fprintf(f, "%d, ", (int)(D->now.tv_sec - n->request_time));
			fprintf(f, "%d", (int)(D->now.tv_sec - n->reply_time));
			if (n->pinged)
				fprintf(f, " (%d)", n->pinged);
			fprintf(f, "%s%s.\n",
				find_node(D, n->id, AF_INET) ? " (known)" : "",
				n->replied ? " (replied)" : "");
		}
		sr = sr->next;
	}

	while (st) {
		fprintf(f, "\nStorage ");
		print_hex(f, st->id, 20);
		fprintf(f, " %d/%d nodes:", st->numpeers, st->maxpeers);
		for (i = 0; i < st->numpeers; i++) {
			char buf[100];
			if (st->peers[i].len == 4) {
				inet_ntop(AF_INET, st->peers[i].ip, buf, 100);
			}
			else if (st->peers[i].len == 16) {
				buf[0] = '[';
				inet_ntop(AF_INET6, st->peers[i].ip, buf + 1, 98);
				strcat(buf, "]");
			}
			else {
				strcpy(buf, "???");
			}
			fprintf(f, " %s:%u (%ld)",
				buf, st->peers[i].port,
				(long)(D->now.tv_sec - st->peers[i].time));
		}
		st = st->next;
	}

	fprintf(f, "\n\n");
	fflush(f);
}

int
dht_init(DHT* OutD, int s, int s6, const unsigned char *id, const unsigned char *v, FILE* df)
{
	int rc;
	pdht D = (pdht)calloc(sizeof(dht), 1);
	*OutD = D;
	D->dht_debug = df;

	D->searches = NULL;
	D->numsearches = 0;

	D->storage = NULL;
	D->numstorage = 0;

	if (s >= 0) {
		D->buckets = (bucket *)calloc(sizeof(struct bucket), 1);
		if (D->buckets == NULL)
			return -1;
		D->buckets->af = AF_INET;

		rc = set_nonblocking(s, 1);
		if (rc < 0)
			goto fail;
	}

	if (s6 >= 0) {
		D->buckets6 = (bucket *)calloc(sizeof(struct bucket), 1);
		if (D->buckets6 == NULL)
			return -1;
		D->buckets6->af = AF_INET6;

		rc = set_nonblocking(s6, 1);
		if (rc < 0)
			goto fail;
	}

	memcpy(D->myid, id, 20);
	if (v) {
		memcpy(D->my_v, "1:v4:", 5);
		memcpy(D->my_v + 5, v, 4);
		D->have_v = 1;
	}
	else {
		D->have_v = 0;
	}

	dht_gettimeofday(&D->now, NULL);

	D->mybucket_grow_time = D->now.tv_sec;
	D->mybucket6_grow_time = D->now.tv_sec;
	D->confirm_nodes_time = D->now.tv_sec + random() % 3;

	D->search_id = random() & 0xFFFF;
	D->search_time = 0;

	D->next_blacklisted = 0;

	D->token_bucket_time = D->now.tv_sec;
	D->token_bucket_tokens = MAX_TOKEN_BUCKET_TOKENS;

	memset(D->secret, 0, sizeof(D->secret));
	rc = rotate_secrets(D);
	if (rc < 0)
		goto fail;

	D->dht_socket = s;
	D->dht_socket6 = s6;

	expire_buckets(D, D->buckets);
	expire_buckets(D, D->buckets6);

	return 1;

fail:
	free(D->buckets);
	D->buckets = NULL;
	free(D->buckets6);
	D->buckets6 = NULL;
	return -1;
}

int
dht_uninit(DHT iD)
{
	pdht D = (pdht)iD;

	if (D->dht_socket < 0 && D->dht_socket6 < 0) {
		errno = EINVAL;
		return -1;
	}

	D->dht_socket = -1;
	D->dht_socket6 = -1;

	while (D->buckets) {
		struct bucket *b = D->buckets;
		D->buckets = b->next;
		while (b->nodes) {
			struct node *n = b->nodes;
			b->nodes = n->next;
			free(n);
		}
		free(b);
	}

	while (D->buckets6) {
		struct bucket *b = D->buckets6;
		D->buckets6 = b->next;
		while (b->nodes) {
			struct node *n = b->nodes;
			b->nodes = n->next;
			free(n);
		}
		free(b);
	}

	while (D->storage) {
		struct storage *st = D->storage;
		D->storage = D->storage->next;
		free(st->peers);
		free(st);
	}

	while (D->searches) {
		struct search *sr = D->searches;
		D->searches = D->searches->next;
		free(sr);
	}

	free(D);
	return 1;
}

/* Rate control for requests we receive. */

static int
token_bucket(pdht D)
{
	if (D->token_bucket_tokens == 0) {
		D->token_bucket_tokens = MIN(MAX_TOKEN_BUCKET_TOKENS,
			100 * (D->now.tv_sec - (int)D->token_bucket_time));
		D->token_bucket_time = D->now.tv_sec;
	}

	if (D->token_bucket_tokens == 0)
		return 0;

	D->token_bucket_tokens--;
	return 1;
}

static int
neighbourhood_maintenance(pdht D, int af)
{
	unsigned char id[20];
	struct bucket *b = find_bucket(D, D->myid, af);
	struct bucket *q;
	struct node *n;

	if (b == NULL)
		return 0;

	memcpy(id, D->myid, 20);
	id[19] = random() & 0xFF;
	q = b;
	if (q->next && (q->count == 0 || (random() & 7) == 0))
		q = b->next;
	if (q->count == 0 || (random() & 7) == 0) {
		struct bucket *r;
		r = previous_bucket(D, b);
		if (r && r->count > 0)
			q = r;
	}

	if (q) {
		/* Since our node-id is the same in both DHTs, it's probably
		   profitable to query both families. */
		int want = D->dht_socket >= 0 && D->dht_socket6 >= 0 ? (WANT4 | WANT6) : -1;
		n = random_node(q);
		if (n) {
			unsigned char tid[4];
			debugf(D, "Sending find_node for%s neighborhood maintenance.\n",
				af == AF_INET6 ? " IPv6" : "");
			make_tid(tid, "fn", 0);
			send_find_node(D, (struct sockaddr*)&n->ss, n->sslen,
				tid, 4, id, want,
				n->reply_time >= D->now.tv_sec - 15);
			pinged(D, n, q);
		}
		return 1;
	}
	return 0;
}

static int
bucket_maintenance(pdht D, int af)
{
	struct bucket *b;

	b = af == AF_INET ? D->buckets : D->buckets6;

	while (b) {
		struct bucket *q;
		if (b->time < D->now.tv_sec - 600) {
			/* This bucket hasn't seen any positive confirmation for a long
			   time.  Pick a random id in this bucket's range, and send
			   a request to a random node. */
			unsigned char id[20];
			struct node *n;
			int rc;

			rc = bucket_random(b, id);
			if (rc < 0)
				memcpy(id, b->first, 20);

			q = b;
			/* If the bucket is empty, we try to fill it from a neighbour.
			   We also sometimes do it gratuitiously to recover from
			   buckets full of broken nodes. */
			if (q->next && (q->count == 0 || (random() & 7) == 0))
				q = b->next;
			if (q->count == 0 || (random() & 7) == 0) {
				struct bucket *r;
				r = previous_bucket(D, b);
				if (r && r->count > 0)
					q = r;
			}

			if (q) {
				n = random_node(q);
				if (n) {
					unsigned char tid[4];
					int want = -1;

					if (D->dht_socket >= 0 && D->dht_socket6 >= 0) {
						struct bucket *otherbucket;
						otherbucket =
							find_bucket(D, id, af == AF_INET ? AF_INET6 : AF_INET);
						if (otherbucket && otherbucket->count < 8)
							/* The corresponding bucket in the other family
							   is emptyish -- querying both is useful. */
							   want = WANT4 | WANT6;
						else if (random() % 37 == 0)
							/* Most of the time, this just adds overhead.
							   However, it might help stitch back one of
							   the DHTs after a network collapse, so query
							   both, but only very occasionally. */
							   want = WANT4 | WANT6;
					}

					debugf(D, "Sending find_node for%s bucket maintenance.\n",
						af == AF_INET6 ? " IPv6" : "");
					make_tid(tid, "fn", 0);
					send_find_node(D, (struct sockaddr*)&n->ss, n->sslen,
						tid, 4, id, want,
						n->reply_time >= D->now.tv_sec - 15);
					pinged(D, n, q);
					/* In order to avoid sending queries back-to-back,
					   give up for now and reschedule us soon. */
					return 1;
				}
			}
		}
		b = b->next;
	}
	return 0;
}

int
dht_periodic(DHT iD, const void *buf, size_t buflen,
const struct sockaddr *from, int fromlen,
time_t *tosleep,
dht_callback *callback, void *closure)
{
	pdht D = (pdht)iD;

	dht_gettimeofday(&D->now, NULL);

	if (buflen > 0) {
		if (!is_martian(D, from) || !node_blacklisted(D, from, fromlen))
		{
			if (((char*)buf)[buflen] != '\0') {
				debugf(D, "Unterminated message.\n");
				errno = EINVAL;
				return -1;
			}

			process_message(D, (unsigned char*)buf, buflen, from, fromlen, callback, closure);
		}
	}

	if (D->now.tv_sec >= D->rotate_secrets_time)
		rotate_secrets(D);

	if (D->now.tv_sec >= D->expire_stuff_time) {
		expire_buckets(D, D->buckets);
		expire_buckets(D, D->buckets6);
		expire_storage(D);
		expire_searches(D);
	}

	if (D->search_time > 0 && D->now.tv_sec >= D->search_time)
	{
		struct search *sr;
		D->search_time = 0;

		sr = D->searches;
		while (sr) {
			if (!sr->done && sr->step_time + 1 <= D->now.tv_sec) {
				search_step(D, sr, callback, closure);
			}

			if (!sr->done) {
				D->search_time = D->now.tv_sec + 1;
			}
			sr = sr->next;
		}
	}

	if (D->now.tv_sec >= D->confirm_nodes_time) {
		int soon = 0;

		soon |= bucket_maintenance(D, AF_INET);
		soon |= bucket_maintenance(D, AF_INET6);

		if (!soon) {
			if (D->mybucket_grow_time >= D->now.tv_sec - 150)
				soon |= neighbourhood_maintenance(D, AF_INET);
			if (D->mybucket6_grow_time >= D->now.tv_sec - 150)
				soon |= neighbourhood_maintenance(D, AF_INET6);
		}

		/* In order to maintain all buckets' age within 600 seconds, worst
		   case is roughly 27 seconds, assuming the table is 22 bits deep.
		   We want to keep a margin for neighborhood maintenance, so keep
		   this within 25 seconds. */
		if (soon)
			D->confirm_nodes_time = D->now.tv_sec + 5 + random() % 20;
		else
			D->confirm_nodes_time = D->now.tv_sec + 60 + random() % 120;
	}

	if (D->confirm_nodes_time > D->now.tv_sec)
		*tosleep = D->confirm_nodes_time - D->now.tv_sec;
	else
		*tosleep = 0;

	if (D->search_time > 0) {
		if (D->search_time <= D->now.tv_sec)
			*tosleep = 0;
		else if (*tosleep > D->search_time - D->now.tv_sec)
			*tosleep = D->search_time - D->now.tv_sec;
	}

	return 1;
}

int
dht_get_nodes(DHT iD, struct sockaddr_in *sin, int *num,
struct sockaddr_in6 *sin6, int *num6)
{
	pdht D = (pdht)iD;

	int i, j;
	struct bucket *b;
	struct node *n;

	i = 0;

	/* For restoring to work without discarding too many nodes, the list
	   must start with the contents of our bucket. */
	b = find_bucket(D, D->myid, AF_INET);
	if (b == NULL)
		goto no_ipv4;

	n = b->nodes;
	while (n && i < *num) {
		if (node_good(D, n)) {
			sin[i] = *(struct sockaddr_in*)&n->ss;
			i++;
		}
		n = n->next;
	}

	b = D->buckets;
	while (b && i < *num) {
		if (!in_bucket(D->myid, b)) {
			n = b->nodes;
			while (n && i < *num) {
				if (node_good(D, n)) {
					sin[i] = *(struct sockaddr_in*)&n->ss;
					i++;
				}
				n = n->next;
			}
		}
		b = b->next;
	}

no_ipv4:

	j = 0;

	b = find_bucket(D, D->myid, AF_INET6);
	if (b == NULL)
		goto no_ipv6;

	n = b->nodes;
	while (n && j < *num6) {
		if (node_good(D, n)) {
			sin6[j] = *(struct sockaddr_in6*)&n->ss;
			j++;
		}
		n = n->next;
	}

	b = D->buckets6;
	while (b && j < *num6) {
		if (!in_bucket(D->myid, b)) {
			n = b->nodes;
			while (n && j < *num6) {
				if (node_good(D, n)) {
					sin6[j] = *(struct sockaddr_in6*)&n->ss;
					j++;
				}
				n = n->next;
			}
		}
		b = b->next;
	}

no_ipv6:

	*num = i;
	*num6 = j;
	return i + j;
}

int
dht_insert_node(DHT iD, const unsigned char *id, struct sockaddr *sa, int salen)
{
	pdht D = (pdht)iD;
	struct node *n;

	if (sa->sa_family != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	n = new_node(D, id, (struct sockaddr*)sa, salen, 0);
	return !!n;
}

int
dht_ping_node(DHT iD, const struct sockaddr *sa, int salen)
{
	pdht D = (pdht)iD;

	unsigned char tid[4];

	debugf(D, "Sending ping.\n");
	make_tid(tid, "pn", 0);
	return send_ping(D, sa, salen, tid, 4);
}

/* We could use a proper bencoding printer and parser, but the format of
   DHT messages is fairly stylised, so this seemed simpler. */

#define CHECK(offset, delta, size)                      \
    if(delta < 0 || offset + delta > size) goto fail

#define INC(offset, delta, size)                        \
    CHECK(offset, delta, size);                         \
    offset += delta

#define COPY(buf, offset, src, delta, size)             \
    CHECK(offset, delta, size);                         \
    memcpy(buf + offset, src, delta);                   \
    offset += delta;

#define ADD_V(buf, offset, size)                        \
    if(D->have_v) {                                        \
        COPY(buf, offset, D->my_v, sizeof(D->my_v), size);    \
	    }

static int
dht_send(pdht D, const void *buf, size_t len, int flags,
const struct sockaddr *sa, int salen)
{
	int s;

	if (salen == 0)
		abort();

	if (node_blacklisted(D, sa, salen)) {
		debugf(D, "Attempting to send to blacklisted node.\n");
		errno = EPERM;
		return -1;
	}

	if (sa->sa_family == AF_INET)
		s = D->dht_socket;
	else if (sa->sa_family == AF_INET6)
		s = D->dht_socket6;
	else
		s = -1;

	if (s < 0) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	return sendto(s, (char *)buf, len, flags, sa, salen);
}

int
send_ping(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len)
{
	char buf[512];
	int i = 0, rc;
	rc = snprintf(buf + i, 512 - i, "d1:ad2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, 20, 512);
	rc = snprintf(buf + i, 512 - i, "e1:q4:ping1:t%d:", tid_len);
	INC(i, rc, 512);
	COPY(buf, i, tid, tid_len, 512);
	ADD_V(buf, i, 512);
	rc = snprintf(buf + i, 512 - i, "1:y1:qe"); INC(i, rc, 512);
	return dht_send(D, buf, i, 0, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
send_pong(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len)
{
	char buf[512];
	int i = 0, rc;
	rc = snprintf(buf + i, 512 - i, "d1:rd2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, 20, 512);
	rc = snprintf(buf + i, 512 - i, "e1:t%d:", tid_len); INC(i, rc, 512);
	COPY(buf, i, tid, tid_len, 512);
	ADD_V(buf, i, 512);
	rc = snprintf(buf + i, 512 - i, "1:y1:re"); INC(i, rc, 512);
	return dht_send(D, buf, i, 0, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
send_find_node(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len,
const unsigned char *target, int want, int confirm)
{
	char buf[512];
	int i = 0, rc;
	rc = snprintf(buf + i, 512 - i, "d1:ad2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, 20, 512);
	rc = snprintf(buf + i, 512 - i, "6:target20:"); INC(i, rc, 512);
	COPY(buf, i, target, 20, 512);
	if (want > 0) {
		rc = snprintf(buf + i, 512 - i, "4:wantl%s%se",
			(want & WANT4) ? "2:n4" : "",
			(want & WANT6) ? "2:n6" : "");
		INC(i, rc, 512);
	}
	rc = snprintf(buf + i, 512 - i, "e1:q9:find_node1:t%d:", tid_len);
	INC(i, rc, 512);
	COPY(buf, i, tid, tid_len, 512);
	ADD_V(buf, i, 512);
	rc = snprintf(buf + i, 512 - i, "1:y1:qe"); INC(i, rc, 512);
	return dht_send(D, buf, i, confirm ? MSG_CONFIRM : 0, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
send_nodes_peers(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len,
const unsigned char *nodes, int nodes_len,
const unsigned char *nodes6, int nodes6_len,
int af, struct storage *st,
const unsigned char *token, int token_len)
{
	char buf[2048];
	int i = 0, rc, j0, j, k, len;

	rc = snprintf(buf + i, 2048 - i, "d1:rd2:id20:"); INC(i, rc, 2048);
	COPY(buf, i, D->myid, 20, 2048);
	if (nodes_len > 0) {
		rc = snprintf(buf + i, 2048 - i, "5:nodes%d:", nodes_len);
		INC(i, rc, 2048);
		COPY(buf, i, nodes, nodes_len, 2048);
	}
	if (nodes6_len > 0) {
		rc = snprintf(buf + i, 2048 - i, "6:nodes6%d:", nodes6_len);
		INC(i, rc, 2048);
		COPY(buf, i, nodes6, nodes6_len, 2048);
	}
	if (token_len > 0) {
		rc = snprintf(buf + i, 2048 - i, "5:token%d:", token_len);
		INC(i, rc, 2048);
		COPY(buf, i, token, token_len, 2048);
	}

	if (st && st->numpeers > 0) {
		/* We treat the storage as a circular list, and serve a randomly
		   chosen slice.  In order to make sure we fit within 1024 octets,
		   we limit ourselves to 50 peers. */

		len = af == AF_INET ? 4 : 16;
		j0 = random() % st->numpeers;
		j = j0;
		k = 0;

		rc = snprintf(buf + i, 2048 - i, "6:valuesl"); INC(i, rc, 2048);
		do {
			if (st->peers[j].len == len) {
				unsigned short swapped;
				swapped = htons(st->peers[j].port);
				rc = snprintf(buf + i, 2048 - i, "%d:", len + 2);
				INC(i, rc, 2048);
				COPY(buf, i, st->peers[j].ip, len, 2048);
				COPY(buf, i, &swapped, 2, 2048);
				k++;
			}
			j = (j + 1) % st->numpeers;
		} while (j != j0 && k < 50);
		rc = snprintf(buf + i, 2048 - i, "e"); INC(i, rc, 2048);
	}

	rc = snprintf(buf + i, 2048 - i, "e1:t%d:", tid_len); INC(i, rc, 2048);
	COPY(buf, i, tid, tid_len, 2048);
	ADD_V(buf, i, 2048);
	rc = snprintf(buf + i, 2048 - i, "1:y1:re"); INC(i, rc, 2048);

	return dht_send(D, buf, i, 0, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

static int
insert_closest_node(unsigned char *nodes, int numnodes,
const unsigned char *id, struct node *n)
{
	int i, size;

	if (n->ss.ss_family == AF_INET)
		size = 26;
	else if (n->ss.ss_family == AF_INET6)
		size = 38;
	else
		abort();

	for (i = 0; i < numnodes; i++) {
		if (id_cmp(n->id, nodes + size * i) == 0)
			return numnodes;
		if (xorcmp(n->id, nodes + size * i, id) < 0)
			break;
	}

	if (i == 8)
		return numnodes;

	if (numnodes < 8)
		numnodes++;

	if (i < numnodes - 1)
		memmove(nodes + size * (i + 1), nodes + size * i,
		size * (numnodes - i - 1));

	if (n->ss.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)&n->ss;
		memcpy(nodes + size * i, n->id, 20);
		memcpy(nodes + size * i + 20, &sin->sin_addr, 4);
		memcpy(nodes + size * i + 24, &sin->sin_port, 2);
	}
	else if (n->ss.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
		memcpy(nodes + size * i, n->id, 20);
		memcpy(nodes + size * i + 20, &sin6->sin6_addr, 16);
		memcpy(nodes + size * i + 36, &sin6->sin6_port, 2);
	}
	else {
		abort();
	}

	return numnodes;
}

static int
buffer_closest_nodes(pdht D, unsigned char *nodes, int numnodes,
const unsigned char *id, struct bucket *b)
{
	struct node *n = b->nodes;
	while (n) {
		if (node_good(D, n))
			numnodes = insert_closest_node(nodes, numnodes, id, n);
		n = n->next;
	}
	return numnodes;
}

int
send_closest_nodes(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len,
const unsigned char *id, int want,
int af, struct storage *st,
const unsigned char *token, int token_len)
{
	unsigned char nodes[8 * 26];
	unsigned char nodes6[8 * 38];
	int numnodes = 0, numnodes6 = 0;
	struct bucket *b;

	if (want < 0)
		want = sa->sa_family == AF_INET ? WANT4 : WANT6;

	if ((want & WANT4)) {
		b = find_bucket(D, id, AF_INET);
		if (b) {
			numnodes = buffer_closest_nodes(D, nodes, numnodes, id, b);
			if (b->next)
				numnodes = buffer_closest_nodes(D, nodes, numnodes, id, b->next);
			b = previous_bucket(D, b);
			if (b)
				numnodes = buffer_closest_nodes(D, nodes, numnodes, id, b);
		}
	}

	if ((want & WANT6)) {
		b = find_bucket(D, id, AF_INET6);
		if (b) {
			numnodes6 = buffer_closest_nodes(D, nodes6, numnodes6, id, b);
			if (b->next)
				numnodes6 =
				buffer_closest_nodes(D, nodes6, numnodes6, id, b->next);
			b = previous_bucket(D, b);
			if (b)
				numnodes6 = buffer_closest_nodes(D, nodes6, numnodes6, id, b);
		}
	}
	debugf(D, "  (%d+%d nodes.)\n", numnodes, numnodes6);

	return send_nodes_peers(D, sa, salen, tid, tid_len,
		nodes, numnodes * 26,
		nodes6, numnodes6 * 38,
		af, st, token, token_len);
}

int
send_get_peers(pdht D, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len, unsigned char *infohash,
int want, int confirm)
{
	char buf[512];
	int i = 0, rc;

	rc = snprintf(buf + i, 512 - i, "d1:ad2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, 20, 512);
	rc = snprintf(buf + i, 512 - i, "9:info_hash20:"); INC(i, rc, 512);
	COPY(buf, i, infohash, 20, 512);
	if (want > 0) {
		rc = snprintf(buf + i, 512 - i, "4:wantl%s%se",
			(want & WANT4) ? "2:n4" : "",
			(want & WANT6) ? "2:n6" : "");
		INC(i, rc, 512);
	}
	rc = snprintf(buf + i, 512 - i, "e1:q9:get_peers1:t%d:", tid_len);
	INC(i, rc, 512);
	COPY(buf, i, tid, tid_len, 512);
	ADD_V(buf, i, 512);
	rc = snprintf(buf + i, 512 - i, "1:y1:qe"); INC(i, rc, 512);
	return dht_send(D, buf, i, confirm ? MSG_CONFIRM : 0, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

int
send_announce_peer(pdht D, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len,
unsigned char *infohash, unsigned short port,
unsigned char *token, int token_len, int confirm)
{
	char buf[512];
	int i = 0, rc;

	rc = snprintf(buf + i, 512 - i, "d1:ad2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, 20, 512);
	rc = snprintf(buf + i, 512 - i, "9:info_hash20:"); INC(i, rc, 512);
	COPY(buf, i, infohash, 20, 512);
	rc = snprintf(buf + i, 512 - i, "4:porti%ue5:token%d:", (unsigned)port,
		token_len);
	INC(i, rc, 512);
	COPY(buf, i, token, token_len, 512);
	rc = snprintf(buf + i, 512 - i, "e1:q13:announce_peer1:t%d:", tid_len);
	INC(i, rc, 512);
	COPY(buf, i, tid, tid_len, 512);
	ADD_V(buf, i, 512);
	rc = snprintf(buf + i, 512 - i, "1:y1:qe"); INC(i, rc, 512);

	return dht_send(D, buf, i, confirm ? 0 : MSG_CONFIRM, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

static int
send_peer_announced(pdht D, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len)
{
	char buf[512];
	int i = 0, rc;

	rc = snprintf(buf + i, 512 - i, "d1:rd2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, 20, 512);
	rc = snprintf(buf + i, 512 - i, "e1:t%d:", tid_len);
	INC(i, rc, 512);
	COPY(buf, i, tid, tid_len, 512);
	ADD_V(buf, i, 512);
	rc = snprintf(buf + i, 512 - i, "1:y1:re"); INC(i, rc, 512);
	return dht_send(D, buf, i, 0, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

static int
send_error(pdht D, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len,
int code, const char *message)
{
	char buf[512];
	int i = 0, rc, message_len;

	message_len = strlen(message);
	rc = snprintf(buf + i, 512 - i, "d1:eli%de%d:", code, message_len);
	INC(i, rc, 512);
	COPY(buf, i, message, message_len, 512);
	rc = snprintf(buf + i, 512 - i, "e1:t%d:", tid_len); INC(i, rc, 512);
	COPY(buf, i, tid, tid_len, 512);
	ADD_V(buf, i, 512);
	rc = snprintf(buf + i, 512 - i, "1:y1:ee"); INC(i, rc, 512);
	return dht_send(D, buf, i, 0, sa, salen);

fail:
	errno = ENOSPC;
	return -1;
}

#undef CHECK
#undef INC
#undef COPY
#undef ADD_V

#ifdef HAVE_MEMMEM

static void *
dht_memmem(const void *haystack, size_t haystacklen,
const void *needle, size_t needlelen)
{
	return memmem(haystack, haystacklen, needle, needlelen);
}

#else

static void *
dht_memmem(const void *haystack, size_t haystacklen,
const void *needle, size_t needlelen)
{
	const char *h = (char *)haystack;
	const char *n = (char *)needle;
	size_t i;

	/* size_t is unsigned */
	if (needlelen > haystacklen)
		return NULL;

	for (i = 0; i <= haystacklen - needlelen; i++) {
		if (memcmp(h + i, n, needlelen) == 0)
			return (void*)(h + i);
	}
	return NULL;
}

#endif

static void
process_message(pdht D, const unsigned char *buf, int buflen,
const struct sockaddr *from, int fromlen,
dht_callback *callback, void *closure
)
{
	int cur = 0;
	b_element e;
	b_parse((char*)buf, buflen, cur, e);

//---public
	unsigned char *tid, *y_return;
	int tid_len, y_len;
	b_find(&e, "t", &tid, tid_len);
	b_find(&e, "y", &y_return, y_len);
	unsigned short ttid;

	if (y_return[0] == 'r'){
		b_element* r;
		b_find(&e, "r", &r);
		if (r == 0)
			goto dontread;

		unsigned char *id;
		int id_len;
		b_find(r, "id", &id, id_len);
		if (id_len == 0)
			goto dontread;

		if (tid_len != 4) {
			debugf(D, "Broken node truncates transaction ids: ");
			debug_printable(D, (unsigned char *)buf, buflen);
			debugf(D, "\n");
			/* This is really annoying, as it means that we will
			time-out all our searches that go through this node.
			Kill it. */
			//blacklist_node(D, id, from, fromlen);
			return;
		}
		if (tid_match(tid, "pn", NULL)) {
			debugf(D, "Pong!\n");
			new_node(D, id, from, fromlen, 2);
		}
		else if (tid_match(tid, "fn", NULL) ||
			tid_match(tid, "gp", NULL)) {
			int gp = 0;
			struct search *sr = NULL;
			if (tid_match(tid, "gp", &ttid)) {
				gp = 1;
				sr = find_search(D, ttid, from->sa_family);
			}

			unsigned char *nodes, *nodes6;
			int nodes_len, nodes6_len;
			b_find(r, "nodes", &nodes, nodes_len);
			b_find(r, "nodes6", &nodes6, nodes6_len);

			debugf(D, "Nodes found (%d+%d)%s!\n", nodes_len / 26, nodes6_len / 38,
				gp ? " for get_peers" : "");
			if (nodes_len % 26 != 0 || nodes6_len % 38 != 0) {
				debugf(D, "Unexpected length for node info!\n");
				blacklist_node(D, id, from, fromlen);
			}
			else if (gp && sr == NULL) {
				debugf(D, "Unknown search!\n");
				new_node(D, id, from, fromlen, 1);
			}
			else {
				int i;
				new_node(D, id, from, fromlen, 2);
				for (i = 0; i < nodes_len / 26; i++) {
					unsigned char *ni = nodes + i * 26;
					struct sockaddr_in sin;
					if (id_cmp(ni, D->myid) == 0)
						continue;
					memset(&sin, 0, sizeof(sin));
					sin.sin_family = AF_INET;
					memcpy(&sin.sin_addr, ni + 20, 4);
					memcpy(&sin.sin_port, ni + 24, 2);
					new_node(D, ni, (struct sockaddr*)&sin, sizeof(sin), 0);
					if (sr && sr->af == AF_INET) {
						insert_search_node(D, ni,
							(struct sockaddr*)&sin,
							sizeof(sin),
							sr, 0, NULL, 0);
					}
				}
				for (i = 0; i < nodes6_len / 38; i++) {
					unsigned char *ni = nodes6 + i * 38;
					struct sockaddr_in6 sin6;
					if (id_cmp(ni, D->myid) == 0)
						continue;
					memset(&sin6, 0, sizeof(sin6));
					sin6.sin6_family = AF_INET6;
					memcpy(&sin6.sin6_addr, ni + 20, 16);
					memcpy(&sin6.sin6_port, ni + 36, 2);
					new_node(D, ni, (struct sockaddr*)&sin6, sizeof(sin6), 0);
					if (sr && sr->af == AF_INET6) {
						insert_search_node(D, ni,
							(struct sockaddr*)&sin6,
							sizeof(sin6),
							sr, 0, NULL, 0);
					}
				}
				if (sr)
					/* Since we received a reply, the number of
					requests in flight has decreased.  Let's push
					another request. */
					search_send_get_peers(D, sr, NULL);
			}
			if (sr) {
				unsigned char* token;
				int token_len;
				b_find(r, "token", &token, token_len);
				if (token_len == 0)
					goto dontread;

				insert_search_node(D, id, from, fromlen, sr,
					1, token, token_len);

				b_element *e_values, *l_values;
				b_find(r, "values", &l_values);
				if (l_values != 0)
				{
					unsigned char values[2048], values6[2048];
					int values_len = 2048, values6_len = 2048;
					int j = 0, j6 = 0;

					b_get(l_values, 0, &e_values);
					if (e_values != 0){
						while (true){
							if (e_values->buf.size() == 6){
								memcpy(values + j, (void*)&e_values->buf[0], e_values->buf.size());
								j += e_values->buf.size();
							}
							else if (e_values->buf.size() == 18){
								memcpy(values + j6, (void*)&e_values->buf[0], e_values->buf.size());
								j6 += e_values->buf.size();
							}

							if (j > values_len || j6 > values6_len)
								break;

							b_next(l_values, &e_values);
							if (e_values == 0)
								break;
						}
					}
					values_len = j; values6_len = j6;

					if (values_len > 0 || values6_len > 0) {

						debugf(D, "Got values (%d+%d)!\n",
							values_len / 6, values6_len / 18);
						if (callback) {
							if (values_len > 0)
								(*callback)((DHT)D, closure, DHT_EVENT_VALUES, sr->id,
								(void*)values, values_len);

							if (values6_len > 0)
								(*callback)((DHT)D, closure, DHT_EVENT_VALUES6, sr->id,
								(void*)values6, values6_len);
						}
					}
				}
			}
		}
		else if (tid_match(tid, "ap", &ttid)) {
			struct search *sr;
			debugf(D, "Got reply to announce_peer.\n");
			sr = find_search(D, ttid, from->sa_family);
			if (!sr) {
				debugf(D, "Unknown search!\n");
				new_node(D, id, from, fromlen, 1);
			}
			else {
				int i;
				new_node(D, id, from, fromlen, 2);
				for (i = 0; i < sr->numnodes; i++)
					if (id_cmp(sr->nodes[i].id, id) == 0) {
						sr->nodes[i].request_time = 0;
						sr->nodes[i].reply_time = D->now.tv_sec;
						sr->nodes[i].acked = 1;
						sr->nodes[i].pinged = 0;
						break;
					}
				/* See comment for gp above. */
				search_send_get_peers(D, sr, NULL);
			}
		}
		else {
			debugf(D, "Unexpected reply: ");
			debug_printable(D, (unsigned char *)buf, buflen);
			debugf(D, "\n");
		}
	}
	else if (y_return[0] ==  'q'){
		unsigned char *q_return;
		int q_len;
		b_find(&e, "q", &q_return, q_len);
		b_element* a;
		b_find(&e, "a", &a);
		if (a == 0)
			goto dontread;

		unsigned char *id;
		int id_len;
		b_find(a, "id", &id, id_len);
		if (id_len == 0)
			goto dontread;

		if (memcmp(q_return, "ping", q_len) == 0){
			debugf(D, "Ping (%d)!\n", tid_len);
			new_node(D, id, from, fromlen, 1);
			debugf(D, "Sending pong.\n");
			send_pong(D, from, fromlen, tid, tid_len);
		}
		else if (memcmp(q_return, "find_node", q_len) == 0)
		{
			unsigned char *target;
			int target_len;
			b_find(a, "target", &target, target_len);
			if (target_len == 0)
				goto dontread;

			int want = -1;
			b_element *e_want, *l_want;
			b_find(a, "want", &e_want);
			if (e_want != 0){
				b_get(e_want, 0, &l_want);
				if (l_want != 0){
					while (true){
						if (memcmp(&l_want->buf[0], "n4", 2) == 0)
							want |= WANT4;
						else if (memcmp(&l_want->buf[0], "n6", 2) == 0)
							want |= WANT6;
						b_next(e_want, &l_want);
						if (l_want == 0)
							break;
					}
				}
			}

			debugf(D, "Find node!\n");
			new_node(D, id, from, fromlen, 1);
			debugf(D, "Sending closest nodes (%d).\n", want);
			send_closest_nodes(D, from, fromlen,
				tid, tid_len, target, want,
				0, NULL, NULL, 0);
		}
		else if (memcmp(q_return, "get_peers", q_len) == 0)
		{
			unsigned char *info_hash;
			int info_hash_len;
			b_find(a, "info_hash", &info_hash, info_hash_len);
			if (info_hash_len == 0)
				goto dontread;

			int want = -1;
			b_element *e_want, *l_want;
			b_find(a, "want", &e_want);
			if (e_want != 0){
				b_get(e_want, 0, &l_want);
				if (l_want != 0){
					while (true){
						if (memcmp(&l_want->buf[0], "n4", 2) == 0)
							want |= WANT4;
						else if (memcmp(&l_want->buf[0], "n6", 2) == 0)
							want |= WANT6;
						b_next(e_want, &l_want);
						if (l_want == 0)
							break;
					}
				}
			}

			debugf(D, "Get_peers!\n");
			debugf_hex(D, "tid:", tid, tid_len);
			new_node(D, id, from, fromlen, 1);
			if (id_cmp(info_hash, zeroes) == 0) {
				debugf(D, "Eek!  Got get_peers with no info_hash.\n");
				send_error(D, from, fromlen, tid, tid_len,
					203, "Get_peers with no info_hash");
				return;
			}else {
				struct storage *st = find_storage(D, info_hash);
				unsigned char token[TOKEN_SIZE];
				make_token(D, from, 0, token);
				if (st && st->numpeers > 0) {
					debugf(D, "Sending found %s peers.\n",
						from->sa_family == AF_INET6 ? " IPv6" : "");
					send_closest_nodes(D, from, fromlen,
						tid, tid_len,
						info_hash, want,
						from->sa_family, st,
						token, TOKEN_SIZE);
				}else {
					debugf(D, "Sending nodes for get_peers.\n");
					send_closest_nodes(D, from, fromlen,
						tid, tid_len, info_hash, want,
						0, NULL, token, TOKEN_SIZE);
				}
			}
		}
		else if (memcmp(q_return, "announce_peer", q_len) == 0)
		{
			unsigned char *info_hash;
			int info_hash_len;
			b_find(a, "info_hash", &info_hash, info_hash_len);
			if (info_hash_len == 0)
				goto dontread;

			unsigned char* token;
			int token_len;
			b_find(a, "token", &token, token_len);
			if (token_len == 0)
				goto dontread;

			int nport;
			unsigned char* port;
			int port_len;
			b_find(a, "port", &port, port_len);
			if (port_len == 0)
				goto dontread;

			std::string sport;
			sport.append((char*)port, port_len);
			nport = atoi(sport.c_str());

			debugf(D, "Announce peer!\n");
			new_node(D, id, from, fromlen, 1);
			if (id_cmp(info_hash, zeroes) == 0) {
				debugf(D, "Announce_peer with no info_hash.\n");
				send_error(D, from, fromlen, tid, tid_len,
					203, "Announce_peer with no info_hash");
				return;
			}
			if (!token_match(D, token, token_len, from)) {
				debugf(D, "Incorrect token for announce_peer.\n");
				send_error(D, from, fromlen, tid, tid_len,
					203, "Announce_peer with wrong token");
				return;
			}
			if (nport == 0) {
				debugf(D, "Announce_peer with forbidden port %d.\n", port);
				send_error(D, from, fromlen, tid, tid_len,
					203, "Announce_peer with forbidden port number");
				return;
			}
			storage_store(D, info_hash, from, nport);
			/* Note that if storage_store failed, we lie to the requestor.
			This is to prevent them from backtracking, and hence
			polluting the DHT. */
			debugf(D, "Sending peer announced.\n");
			send_peer_announced(D, from, fromlen, tid, tid_len);
		}

		if (!token_bucket(D)) {
			debugf(D, "Dropping request due to rate limiting.\n");
		}
	}
	return;

dontread:
	// if (y_return[0] == 'e')
	debugf(D, "Unparseable message: ");
	debug_printable(D, (unsigned char *)buf, buflen);
	debugf(D, "\n");
}