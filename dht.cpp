/*
Copyright (c) 2009-2011 by Juliusz Chroboczek
Copyright (c) 2009-2011 by shuo sun(dds_sun@hotmail.com)

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

#define IDLEN 20
struct node {
	unsigned char id[IDLEN];
	struct sockaddr_storage ss;
	int sslen;
	time_t time;                /* time of last message received */
	time_t reply_time;          /* time of last correct reply received */
	time_t pinged_time;         /* time of last request */
	int pinged;                 /* how many requests we sent since last reply */
};

struct gp_node {
	struct sockaddr_storage ss;
	int sslen;
};

struct search_node {
	unsigned char id[IDLEN];
	struct sockaddr_storage ss;
	int sslen;
	time_t request_time;        /* the time of the last unanswered request */
	time_t reply_time;          /* the time of the last reply */
	int pinged;
	unsigned char token[40];
	int token_len;
	int replied;                /* whether we have received a reply */
};

/* When performing a search, we search for up to SEARCH_NODES closest nodes
   to the destination, and use the additional ones to backtrack if any of
   the target 8 turn out to be dead. */
#define SEARCH_NODES 14

#define MAXGETPEER   3
#define MAXANNOUNCE  5

///Notice that search is used to modify and query the two operations
struct search {
	unsigned short tid;
	int af;
	time_t step_time;           /* the time of the last search_step */
	unsigned char id[IDLEN];
	unsigned short pg;        /* 0 for pure get*/
	std::vector<char> buf;     //Data to be published
	int done;
	struct search_node nodes[SEARCH_NODES];
	int numnodes;
	struct search *next;
	dht_callback *callback;
	void *closure;

	int sequence;
	///announce and get peer
	int getpeer;
	std::list<gp_node> gpnode;//allready return node, announce peer user too
	std::map<std::vector<char>, int> gpresult;//Return result ranking
};

struct peer {
	unsigned short head;///0 normal, 1 is head
	time_t time;
	std::vector<char> buf;     //data block
};

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
	unsigned char id[IDLEN];
	struct peer speer;
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

static const unsigned char zeroes[IDLEN] = { 0 };
static const unsigned char ones[IDLEN] = {
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

	unsigned char myid[IDLEN];
	int have_v;
	unsigned char my_v[9];
	unsigned char secret[8];
	unsigned char oldsecret[8];

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

	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	std::map<std::vector<unsigned char>, node> routetable;
	std::map<std::vector<unsigned char>, node> routetable6;

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
static int send_search(pdht D, const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len,
	unsigned char *infohash, int want, int confirm);
static int send_get_peers(pdht D, const struct sockaddr *hsa, int hsalen,
	const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len,
	unsigned char *infohash, int want, int confirm, int sequence);
static int send_announce_peer(pdht D, const struct sockaddr *hsa, int hsalen, 
	const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len,
	unsigned char *info_hash, int info_hash_len,
	unsigned char *value, int value_len,
	unsigned char *token, int token_len, int confirm, int sequence);
static int send_peer_announced(pdht D, const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len);
static int send_error(pdht D, const struct sockaddr *sa, int salen,
	unsigned char *tid, int tid_len,
	int code, const char *message);
static void process_message(pdht D, const unsigned char *buf, int buflen,
	const struct sockaddr *from, int fromlen);

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
	return memcmp(id1, id2, IDLEN);
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
	for (i = 0; i < IDLEN; i++) {
		if (id1[i] != id2[i])
			break;
	}

	if (i == IDLEN)
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
	for (i = 0; i < IDLEN; i++) {
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

/* Every bucket contains an unordered list of nodes. */
static struct node *
find_node(pdht D, const unsigned char *id, int af)
{
	std::map<std::vector<unsigned char>, node> *r = af == AF_INET ? &D->routetable : &D->routetable6;

	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);
	std::map<std::vector<unsigned char>, node>::iterator iter = r->find(k);
	if (iter != r->end()){
		return &iter->second;
	}

	return NULL;
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

/* Called whenever we send a request to a node, increases the ping count
   and, if that reaches 3, sends a ping to a new candidate. */
static void 
pinged(pdht D, struct node *n)
{
	n->pinged++;
	n->pinged_time = D->now.tv_sec;
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
			pinged(D, n);
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

/* We just learnt about a node, not necessarily a new one.  Confirm is 1 if
   the node sent a message, 2 if it sent us a reply. */
static struct node *
new_node(pdht D, const unsigned char *id, const struct sockaddr *sa, int salen,
int confirm)
{
	if (id_cmp(id, D->myid) == 0)
		return NULL;

	if (is_martian(D, sa) || node_blacklisted(D, sa, salen))
		return NULL;

	std::map<std::vector<unsigned char>, node> *r = sa->sa_family == AF_INET ? &D->routetable : &D->routetable6;
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);

	std::map<std::vector<unsigned char>, node>::iterator iter = r->find(k);
	if (iter != r->end()){
		struct node *n = &iter->second;
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
	}else{
		//new node
		struct node* n = &(*r)[k];

		if (sa->sa_family == AF_INET)
			D->mybucket_grow_time = D->now.tv_sec;
		else
			D->mybucket6_grow_time = D->now.tv_sec;

		/* Create a new node. */
		memcpy(n->id, id, IDLEN);
		memcpy(&n->ss, sa, salen);
		n->sslen = salen;
		n->time = confirm ? D->now.tv_sec : 0;
		n->reply_time = confirm >= 2 ? D->now.tv_sec : 0;
		return n;
	}
	return 0;
}

/* Called periodically to purge known-bad nodes.  Note that we're very
   conservative here: broken nodes in the table don't do much harm, we'll
   recover as soon as we find better ones. */
static int
expire_buckets(pdht D, std::map<std::vector<unsigned char>, node> *routetable)
{

	std::map<std::vector<unsigned char>, node>::iterator iter = routetable->begin();
	for (; iter != routetable->end(); ){
		if (iter->second.pinged >= 4){
			iter = routetable->erase(iter);
		}else
			iter++;
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
	memcpy(n->id, id, IDLEN);

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
search_send(pdht D, struct search *sr, struct search_node *n)
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

	debugf(D, "Sending search.\n");
	make_tid(tid, "sr", sr->tid);
	debugf_hex(D, "tid:", tid, 4);
	send_search(D, (struct sockaddr*)&n->ss, n->sslen, tid, 4, sr->id, -1,
		n->reply_time >= D->now.tv_sec - 15);
	n->pinged++;
	n->request_time = D->now.tv_sec;
	/* If the node happens to be in our main routing table, mark it
	as pinged. */
	node = find_node(D, n->id, n->ss.ss_family);
	if (node) pinged(D, node);
	return 1;
}

/* This must always return 0 or 1, never -1, not even on failure (see below). */
static int
get_peers_send(pdht D, struct search *sr, struct search_node *n)
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
	send_get_peers(D, n->ss.ss_family == AF_INET ? (struct sockaddr*)&D->sin : (struct sockaddr*) &D->sin6,
		n->ss.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
		(struct sockaddr*)&n->ss, n->sslen, tid, 4, sr->id, -1,
		n->reply_time >= D->now.tv_sec - 15, 0);
	n->pinged++;
	n->request_time = D->now.tv_sec;
	/* If the node happens to be in our main routing table, mark it
	   as pinged. */
	node = find_node(D, n->id, n->ss.ss_family);
	if (node) pinged(D, node);
	return 1;
}

/* When a search is in progress, we periodically call search_step to send
   further requests. */
static void
search_step(pdht D, struct search *sr)
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
		if (sr->pg == 0) {
			///begin step get peer
			if (!sr->getpeer){
				sr->getpeer = 1;
				int sendap = 0;
				for (i = 0; i < sr->numnodes; i++) {
					struct search_node *n = &sr->nodes[i];
					struct node *node;
					unsigned char tid[4];
					if (n->pinged >= 3)
						continue;
					/* A proposed extension to the protocol consists in
					omitting the token when storage tables are full.  While
					I don't think this makes a lot of sense -- just sending
					a positive reply is just as good --, let's deal with it. */
					sendap = 1;
					debugf(D, "Sending announce_peer.\n");
					make_tid(tid, "gp", sr->tid);
					search_send(D, sr, &sr->nodes[i]);
					n->pinged++;
					n->request_time = D->now.tv_sec;
					node = find_node(D, n->id, n->ss.ss_family);
					if (node) pinged(D, node);
					break;
				}
				if (!sendap){
					debugf(D, "Sending announce_peer error.\n");
				}
			}
			else if (sr->gpnode.size() < MAXGETPEER && D->now.tv_sec - sr->step_time > 60){
				///outtime try again
			}
			else if (sr->gpnode.size() >= MAXGETPEER){
				goto done;
			}

		}else {
			///begin step announce peer
			if (!sr->getpeer){
				sr->getpeer = 1;
				int sendap = 0;
				for (i = 0; i < sr->numnodes; i++) {
					struct search_node *n = &sr->nodes[i];
					struct node *node;
					unsigned char tid[4];
					if (n->pinged >= 3)
						continue;
					/* A proposed extension to the protocol consists in
					   omitting the token when storage tables are full.  While
					   I don't think this makes a lot of sense -- just sending
					   a positive reply is just as good --, let's deal with it. */
					sendap = 1;
					debugf(D, "Sending announce_peer.\n");
					make_tid(tid, "ap", sr->tid);
					send_announce_peer(D, n->ss.ss_family == AF_INET ? (struct sockaddr*)&D->sin : (struct sockaddr*)&D->sin6,
						n->ss.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
						(struct sockaddr*)&n->ss,
						sizeof(struct sockaddr_storage),
						tid, 4, sr->id, IDLEN,
						(unsigned char*)&sr->buf[0], sr->buf.size(),
						n->token, n->token_len,
						n->reply_time >= D->now.tv_sec - 15, 0);
					n->pinged++;
					n->request_time = D->now.tv_sec;
					node = find_node(D, n->id, n->ss.ss_family);
					if (node) pinged(D, node);
					break;
				}
				if (!sendap){
					debugf(D, "Sending announce_peer error.\n");
				}
			}
			else if (sr->gpnode.size() < MAXANNOUNCE && D->now.tv_sec - sr->step_time > 60){
				///outtime try again
			}
			else if (sr->gpnode.size() >= MAXANNOUNCE){
				goto done;
			}
		}
		sr->step_time = D->now.tv_sec;
		return;
	}

	if (sr->step_time + 15 >= D->now.tv_sec)
		return;
	
	j = 0;
	for (i = 0; i < sr->numnodes; i++) {
		j += search_send(D, sr, &sr->nodes[i]);
		if (j >= 3)
			break;
	}
	sr->step_time = D->now.tv_sec;
	return;

done:
	sr->done = 1;
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
insert_search_bucket(pdht D, struct search *sr)
{
	std::map<std::vector<unsigned char>, node> *r = sr->af == AF_INET ? &D->routetable : &D->routetable6;
	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	for (; iter != r->end(); iter++)
	{
		struct node *n = &iter->second;
		insert_search_node(D, n->id, (struct sockaddr*)&n->ss, n->sslen,
			sr, 0, NULL, 0);
	}
}

/* Start a search.  If port is non-zero, perform an announce when the
   search is complete. */
int
dht_search(DHT iD, const unsigned char *id, int pg, int af,
dht_callback *callback, void *closure, const char* buf, int len)
{
	pdht D = (pdht)iD;

	struct search *sr;
	struct storage *st;

	/* Try to answer this search locally.  In a fully grown DHT this
	   is very unlikely, but people are running modified versions of
	   this code in private DHTs with very few nodes.  What's wrong
	   with flooding? */
	if (callback) {
		st = find_storage(D, id);
		if (st) {
			(*callback)((DHT)D, closure, DHT_EVENT_VALUES, id,
				(void*)&st->speer.buf[0], st->speer.buf.size());
		}
	}

	sr = new_search(D);
	if (sr == NULL) {
		errno = ENOSPC;
		return -1;
	}
	sr->af = af;
	sr->tid = D->search_id++;
	sr->step_time = 0;
	memcpy(sr->id, id, IDLEN);
	sr->done = 0;
	sr->numnodes = 0;
	sr->pg = pg;
	sr->callback = callback;
	sr->closure = closure;
	sr->sequence = 0;
	sr->getpeer = 0;
	if (pg && len){
		sr->buf.resize(len);
		memcpy(&sr->buf[0], buf, len);
	}

	insert_search_bucket(D, sr);

	search_step(D, sr);
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
const char* buf, int len)
{
	struct storage *st;

	st = find_storage(D, id);

	if (st == NULL) {
		if (D->numstorage >= DHT_MAX_HASHES)
			return -1;
		st = (storage *)calloc(1, sizeof(struct storage));
		if (st == NULL) return -1;
		memcpy(st->id, id, IDLEN);
		st->next = D->storage;
		D->storage = st;
		D->numstorage++;
	}
	
	st->speer.time = D->now.tv_sec;
	st->speer.buf.resize(len);
	memcpy(&st->speer.buf[0], buf, len);
	return 1;
}

static int
expire_storage(pdht D)
{
	struct storage *st = D->storage, *previous = NULL;
	while (st) {
		if (st->speer.time < D->now.tv_sec - 32 * 60) {
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
dht_nodes(DHT iD, int af, int *good_return, int *dubious_return,
int *incoming_return)
{
	pdht D = (pdht)iD;
	int good = 0, dubious = 0, incoming = 0;
	std::map<std::vector<unsigned char>, node> *r = af == AF_INET ? &D->routetable : &D->routetable6;
	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	for (; iter != r->end(); iter++)
	{
		node *n = &iter->second;
		if (node_good(D, n)) {
			good++;
			if (n->time > n->reply_time)
				incoming++;
		}
		else {
			dubious++;
		}
	}

	if (good_return)
		*good_return = good;
	if (dubious_return)
		*dubious_return = dubious;
	if (incoming_return)
		*incoming_return = incoming;
	return good + dubious;
}

static void
dump_bucket(pdht D, FILE *f, std::map<std::vector<unsigned char>, node> *r)
{
	fprintf(f, "rount ");
	fprintf(f, " count %d :\n",
		r->size());

	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	for (; iter != r->end(); iter++){
		node* n = &iter->second;
		char buf[512];
		unsigned short port;
		fprintf(f, "    Node ");
		print_hex(f, n->id, IDLEN);
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
	}
}

void
dht_dump_tables(DHT iD, FILE *f)
{
	pdht D = (pdht)iD;

	int i;
	std::map<std::vector<unsigned char>, node> *b;
	struct storage *st = D->storage;
	struct search *sr = D->searches;

	fprintf(f, "My id ");
	print_hex(f, D->myid, IDLEN);
	fprintf(f, "\n");

	b = &D->routetable;
	dump_bucket(D, f, b);

	fprintf(f, "\n");

	b = &D->routetable6;
	dump_bucket(D, f, b);

	while (sr) {
		fprintf(f, "\nSearch%s id ", sr->af == AF_INET6 ? " (IPv6)" : "");
		print_hex(f, sr->id, IDLEN);
		fprintf(f, " age %d%s\n", (int)(D->now.tv_sec - sr->step_time),
			sr->done ? " (done)" : "");
		for (i = 0; i < sr->numnodes; i++) {
			struct search_node *n = &sr->nodes[i];
			fprintf(f, "Node %d id ", i);
			print_hex(f, n->id, IDLEN);
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
		print_hex(f, st->id, IDLEN);

		fprintf(f, "[");
		print_hex(f, (unsigned char*)&st->speer.buf[0], st->speer.buf.size());
		fprintf(f, "](%ld)", (long)(D->now.tv_sec - st->speer.time));
		st = st->next;
	}
	fprintf(f, "\n\n");
	fflush(f);
}

int
dht_init(DHT* OutD, int s, int s6, const unsigned char *id, 
		const unsigned char *v, FILE* df,
		struct sockaddr_in &sin,struct sockaddr_in6 &sin6)
{
	int rc;
	pdht D = new dht;
	*OutD = D;
	D->dht_debug = df;

	D->searches = NULL;
	D->numsearches = 0;

	D->storage = NULL;
	D->numstorage = 0;

	if (s >= 0) {
		rc = set_nonblocking(s, 1);
		if (rc < 0)
			goto fail;
	}

	if (s6 >= 0) {
		rc = set_nonblocking(s6, 1);
		if (rc < 0)
			goto fail;
	}

	memcpy(D->myid, id, IDLEN);
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

	expire_buckets(D, &D->routetable);
	expire_buckets(D, &D->routetable6);

	memcpy(&D->sin, &sin, sizeof(sockaddr_in));
	memcpy(&D->sin6, &sin6, sizeof(sockaddr_in6));

	return 1;
fail:
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

	while (D->storage) {
		struct storage *st = D->storage;
		D->storage = D->storage->next;
		free(st);
	}

	while (D->searches) {
		struct search *sr = D->searches;
		D->searches = D->searches->next;
		free(sr);
	}

	delete D;
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

///要整理当前myid一定范围内的目前先随机
///The current K barrels, a barrel of K, or near the node of a barrel of K search
static int
neighbourhood_maintenance(pdht D, int af)
{
	std::map<std::vector<unsigned char>, node> *r = af == AF_INET ? &D->routetable : &D->routetable6;
	if (0 == r->size())
		return 0;

	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	int ir = random() % r->size();

	for (int i = 0; iter != r->end(), i < ir ; iter++, i++){}
	node* n = &iter->second;
	if (n) {
		int want = D->dht_socket >= 0 && D->dht_socket6 >= 0 ? (WANT4 | WANT6) : -1;
		unsigned char tid[4];
		debugf(D, "Sending find_node for%s neighborhood maintenance.\n",
			af == AF_INET6 ? " IPv6" : "");
		make_tid(tid, "fn", 0);
		send_find_node(D, (struct sockaddr*)&n->ss, n->sslen,
			tid, 4, D->myid, want,
			n->reply_time >= D->now.tv_sec - 15);
		pinged(D, n);
		return 1;
	}
	return 0;
}

static int
bucket_maintenance(pdht D, int af)
{
	std::map<std::vector<unsigned char>, node> *r = af == AF_INET ? &D->routetable : &D->routetable6;
	if (0 == r->size())
		return 0;

	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	int ir = random() % r->size();

	for (int i = 0; iter != r->end(), i < ir; iter++, i++){}
	node* n = &iter->second;
	if (n) {
		unsigned char id[IDLEN];
		dht_random_bytes(id, 20);

		unsigned char tid[4];
		int want = D->dht_socket >= 0 && D->dht_socket6 >= 0 ? (WANT4 | WANT6) : -1;
		debugf(D, "Sending find_node for%s bucket maintenance.\n",
			af == AF_INET6 ? " IPv6" : "");
		make_tid(tid, "fn", 0);
		send_find_node(D, (struct sockaddr*)&n->ss, n->sslen,
			tid, 4, id, want,
			n->reply_time >= D->now.tv_sec - 15);
		pinged(D, n);
		/* In order to avoid sending queries back-to-back,
		give up for now and reschedule us soon. */
		return 1;
	}
	return 0;
}

int
dht_periodic(DHT iD, const void *buf, size_t buflen,
const struct sockaddr *from, int fromlen,
time_t *tosleep)
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

			process_message(D, (unsigned char*)buf, buflen, from, fromlen);
		}
	}

	if (D->now.tv_sec >= D->rotate_secrets_time)
		rotate_secrets(D);

	if (D->now.tv_sec >= D->expire_stuff_time) {
		expire_buckets(D, &D->routetable);
		expire_buckets(D, &D->routetable6);
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
				search_step(D, sr);
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
			D->confirm_nodes_time = D->now.tv_sec + 5 + random() % IDLEN;
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
	std::map<std::vector<unsigned char>, node> *r = &D->routetable;
	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	int i = 0;
	for (; iter != r->end(); iter++){
		node* n = &iter->second;
		if (i <= *num){
			if (node_good(D, n)) {
			sin[i++] = *(struct sockaddr_in*)&n->ss;
			}
		}else
			break;

	}
	
	r = &D->routetable6;
	int j = 0;
	for (; iter != r->end(); iter++){
		node* n = &iter->second;
		if (j <= *num6){
			if (node_good(D, n) && j <= *num6) {
				sin6[j++] = *(struct sockaddr_in6*)&n->ss;
			}
		}
		else
			break;
	}

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
	COPY(buf, i, D->myid, IDLEN, 512);
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
	COPY(buf, i, D->myid, IDLEN, 512);
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
send_nodes_peers(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len,
const unsigned char *nodes, int nodes_len,
const unsigned char *nodes6, int nodes6_len,
int af, struct storage *st,
const unsigned char *token, int token_len)
{
	char buf[2048];
	int i = 0, rc;

	rc = snprintf(buf + i, 2048 - i, "d1:rd2:id20:"); INC(i, rc, 2048);
	COPY(buf, i, D->myid, IDLEN, 2048);
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

	if (st) {
		/* We treat the storage as a circular list, and serve a randomly
		   chosen slice.  In order to make sure we fit within 1024 octets,
		   we limit ourselves to 50 peers. */
		rc = snprintf(buf + i, 2048 - i, "5:value"); INC(i, rc, 2048);
		rc = snprintf(buf + i, 2048 - i, "%d:", st->speer.buf.size());INC(i, rc, 2048);
		COPY(buf, i, &st->speer.buf[0], st->speer.buf.size(), 2048);
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

int
send_find_node(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len,
const unsigned char *target, int want, int confirm)
{
	char buf[512];
	int i = 0, rc;
	rc = snprintf(buf + i, 512 - i, "d1:ad2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, IDLEN, 512);
	rc = snprintf(buf + i, 512 - i, "6:target20:"); INC(i, rc, 512);
	COPY(buf, i, target, IDLEN, 512);
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
		memcpy(nodes + size * i, n->id, IDLEN);
		memcpy(nodes + size * i + IDLEN, &sin->sin_addr, 4);
		memcpy(nodes + size * i + 24, &sin->sin_port, 2);
	}
	else if (n->ss.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
		memcpy(nodes + size * i, n->id, IDLEN);
		memcpy(nodes + size * i + IDLEN, &sin6->sin6_addr, 16);
		memcpy(nodes + size * i + 36, &sin6->sin6_port, 2);
	}
	else {
		abort();
	}

	return numnodes;
}

static int
buffer_closest_nodes(pdht D, unsigned char *nodes, int numnodes,
const unsigned char *id, std::map<std::vector<unsigned char>, node> *r)
{
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);

	std::map<std::vector<unsigned char>, node>::iterator iter2, iter = iter2 = r->lower_bound(k);
	for (int i = 0; iter != r->end() && i < 8 ; iter--)
	{
		struct node *n = &iter->second;
		if (node_good(D, n)){
			i++;
			numnodes = insert_closest_node(nodes, numnodes, id, n);
		}
			

	}

	for (int i = 0; iter2 != r->end() && i < 8; iter2++)
	{
		struct node *n = &iter2->second;
		if (node_good(D, n)){
			i++;
			numnodes = insert_closest_node(nodes, numnodes, id, n);
		}
			
	}
	return numnodes;
}

static node* neighbourhoodup(pdht D, const unsigned char *id,
	std::map<std::vector<unsigned char>, node> *r)
{
	if (r->empty())
		return 0;
	
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);
	std::map<std::vector<unsigned char>, node>::iterator iter, iter2 = r->lower_bound(k);
	iter = iter2;
	iter--;
	for (int i = 0; i < int(r->size()*2); i++){
		if (iter == r->end()){
			iter--;
			continue;
		}
		if (iter == iter2){
			return 0;
		}
		struct node *n = &iter->second;
		if (node_good(D, n)){
			return n;
		}
	}
	return 0;
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
	if (want < 0)
		want = sa->sa_family == AF_INET ? WANT4 : WANT6;

	if ((want & WANT4)) {
		numnodes = buffer_closest_nodes(D, nodes, numnodes, id, &D->routetable);
	}

	if ((want & WANT6)) {
		numnodes = buffer_closest_nodes(D, nodes6, numnodes6, id, &D->routetable6);
	}
	debugf(D, "  (%d+%d nodes.)\n", numnodes, numnodes6);

	return send_nodes_peers(D, sa, salen, tid, tid_len,
		nodes, numnodes * 26,
		nodes6, numnodes6 * 38,
		af, st, token, token_len);
}

int
send_search(pdht D, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len, unsigned char *infohash,
int want, int confirm)
{
	char buf[512];
	int i = 0, rc;

	rc = snprintf(buf + i, 512 - i, "d1:ad2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, IDLEN, 512);
	rc = snprintf(buf + i, 512 - i, "9:info_hash20:"); INC(i, rc, 512);
	COPY(buf, i, infohash, 20, 512);
	if (want > 0) {
		rc = snprintf(buf + i, 512 - i, "4:wantl%s%se",
			(want & WANT4) ? "2:n4" : "",
			(want & WANT6) ? "2:n6" : "");
		INC(i, rc, 512);
	}
	rc = snprintf(buf + i, 512 - i, "e1:q6:search1:t%d:", tid_len);
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
send_get_peers(pdht D, const struct sockaddr *hsa, int hsalen,
const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len, unsigned char *infohash,
int want, int confirm, int sequence)
{
	char buf[512];
	int i = 0, rc;

	rc = snprintf(buf + i, 512 - i, "d1:ad2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, IDLEN, 512);
	rc = snprintf(buf + i, 512 - i, "9:info_hash20:"); INC(i, rc, 512);
	COPY(buf, i, infohash, 20, 512);
	if (want > 0) {
		rc = snprintf(buf + i, 512 - i, "4:wantl%s%se",
			(want & WANT4) ? "2:n4" : "",
			(want & WANT6) ? "2:n6" : "");
		INC(i, rc, 512);
	}
	if (hsa->sa_family == AF_INET){
		sockaddr_in* sd_in = (sockaddr_in*)hsa;
		rc = snprintf(buf + i, 512 - i, "5:order%d:", 6); INC(i, rc, 512);
		COPY(buf, i, &sd_in->sin_addr, 4, 512);
		COPY(buf, i, &sd_in->sin_port, 2, 512);
	}
	else{
		sockaddr_in6* sd_in = (sockaddr_in6*)hsa;
		rc = snprintf(buf + i, 512 - i, "5:order%d:", 18); INC(i, rc, 512);
		COPY(buf, i, &sd_in->sin6_addr, 16, 512);
		COPY(buf, i, &sd_in->sin6_port, 2, 512);
	}
	rc = snprintf(buf + i, 512 - i, "8:sequence%d:", sizeof(int)); INC(i, rc, 512);
	COPY(buf, i, &sequence, sizeof(int), 512);
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

static int
send_announce_peer(pdht D, const struct sockaddr* hsa, int hsalen, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len,
unsigned char *info_hash, int info_hash_len,
unsigned char *value, int value_len,
unsigned char *token, int token_len, int confirm, int sequence)
{
	char buf[512];
	int i = 0, rc;

	rc = snprintf(buf + i, 512 - i, "d1:ad2:id20:"); INC(i, rc, 512);
	COPY(buf, i, D->myid, IDLEN, 512);
	rc = snprintf(buf + i, 512 - i, "9:info_hash20:"); INC(i, rc, 512);
	COPY(buf, i, info_hash, IDLEN, 512);
	rc = snprintf(buf + i, 512 - i, "5:value%d:", value_len); INC(i, rc, 512);
	COPY(buf, i, value, value_len, 512);
	rc = snprintf(buf + i, 512 - i, "5:token%d:", token_len);
	INC(i, rc, 512);
	COPY(buf, i, token, token_len, 512);
	if (hsa->sa_family == AF_INET){
		sockaddr_in* sd_in = (sockaddr_in*)hsa;
		rc = snprintf(buf + i, 512 - i, "5:order%d:", 6);INC(i, rc, 512);
		COPY(buf, i, &sd_in->sin_addr, 4, 512);
		COPY(buf, i, &sd_in->sin_port, 2, 512);
	}else{
		sockaddr_in6* sd_in = (sockaddr_in6*)hsa;
		rc = snprintf(buf + i, 512 - i, "5:order%d:", 18); INC(i, rc, 512);
		COPY(buf, i, &sd_in->sin6_addr, 16, 512);
		COPY(buf, i, &sd_in->sin6_port, 2, 512);
	}
	rc = snprintf(buf + i, 512 - i, "8:sequence%d:", sizeof(int)); INC(i, rc, 512);
	COPY(buf, i, &sequence, sizeof(int), 512);

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
	COPY(buf, i, D->myid, IDLEN, 512);
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

static void
process_message(pdht D, const unsigned char *buf, int buflen,
const struct sockaddr *from, int fromlen
)
{
	int cur = 0;
	b_element e;
	b_parse((char*)buf, buflen, cur, e);

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
		else if (tid_match(tid, "gp", NULL)) {
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
					memcpy(&sin.sin_addr, ni + IDLEN, 4);
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
					memcpy(&sin6.sin6_addr, ni + IDLEN, 16);
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
					search_send(D, sr, NULL);
			}
			if (sr) {
				unsigned char* token;
				int token_len;
				b_find(r, "token", &token, token_len);
				if (token_len == 0)
					goto dontread;

				insert_search_node(D, id, from, fromlen, sr,
					1, token, token_len);

				unsigned char* value;
				int value_len;
				b_find(r, "value", &value, value_len);
				if (value_len != 0){
					if (sr->callback) {
						if (value_len > 0)
							(*sr->callback)((DHT)D, sr->closure, DHT_EVENT_VALUES, sr->id,
							(void*)value, value_len);
					}
				}
			}
		}
		else if (tid_match(tid, "sr", NULL)) {
			int sh = 0;
			struct search *sr = NULL;
			if (tid_match(tid, "sr", &ttid)) {
				sh = 1;
				sr = find_search(D, ttid, from->sa_family);
			}

			unsigned char *nodes, *nodes6;
			int nodes_len, nodes6_len;
			b_find(r, "nodes", &nodes, nodes_len);
			b_find(r, "nodes6", &nodes6, nodes6_len);

			debugf(D, "Nodes found (%d+%d)%s!\n", nodes_len / 26, nodes6_len / 38,
				sh ? " for search" : "");
			if (nodes_len % 26 != 0 || nodes6_len % 38 != 0) {
				debugf(D, "Unexpected length for node info!\n");
				blacklist_node(D, id, from, fromlen);
			}
			else if (sh && sr == NULL) {
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
					memcpy(&sin.sin_addr, ni + IDLEN, 4);
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
					memcpy(&sin6.sin6_addr, ni + IDLEN, 16);
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
					search_send(D, sr, NULL);
			}
			if (sr) {
				unsigned char* token;
				int token_len;
				b_find(r, "token", &token, token_len);
				if (token_len == 0)
					goto dontread;

				insert_search_node(D, id, from, fromlen, sr,
					1, token, token_len);
			}
		}
		else if (tid_match(tid, "fn", NULL)) {
			unsigned char *nodes, *nodes6;
			int nodes_len, nodes6_len;
			b_find(r, "nodes", &nodes, nodes_len);
			b_find(r, "nodes6", &nodes6, nodes6_len);

			if (nodes_len % 26 != 0 || nodes6_len % 38 != 0) {
				debugf(D, "Unexpected length for node info!\n");
				blacklist_node(D, id, from, fromlen);
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
					memcpy(&sin.sin_addr, ni + IDLEN, 4);
					memcpy(&sin.sin_port, ni + 24, 2);
					new_node(D, ni, (struct sockaddr*)&sin, sizeof(sin), 0);
				}
				for (i = 0; i < nodes6_len / 38; i++) {
					unsigned char *ni = nodes6 + i * 38;
					struct sockaddr_in6 sin6;
					if (id_cmp(ni, D->myid) == 0)
						continue;
					memset(&sin6, 0, sizeof(sin6));
					sin6.sin6_family = AF_INET6;
					memcpy(&sin6.sin6_addr, ni + IDLEN, 16);
					memcpy(&sin6.sin6_port, ni + 36, 2);
					new_node(D, ni, (struct sockaddr*)&sin6, sizeof(sin6), 0);
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
						sr->nodes[i].pinged = 0;
						break;
					}

				gp_node n;
				memcpy(&n.ss, &from, fromlen);
				n.sslen = fromlen;
				sr->gpnode.push_back(n);
				/* See comment for gp above. */
				//search_send(D, sr, NULL);
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

			unsigned char* order;
			int order_len;
			b_find(a, "order", &order, order_len);
			if (order_len == 0)
				goto dontread;

			unsigned char* sequence;
			int sequence_len;
			b_find(a, "sequence", &sequence, sequence_len);
			if (sequence_len == 0)
				goto dontread;
			int isequence = -1;
			memcpy(&isequence, sequence, sequence_len);
			if (isequence == -1)
				goto dontread;

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

				struct sockaddr_in order_in;
				struct sockaddr_in6 order_in6;
				struct sockaddr* to;
				int to_len;
				if (order_len == 6){
					order_in.sin_family = AF_INET;
					memcpy((void*)&order_in.sin_addr, order, 4);
					memcpy((void*)&order_in.sin_port, order + 4, 2);
					to = (sockaddr*)&order_in;
					to_len = sizeof(order_in);
				}
				else if (order_len == 18){
					order_in6.sin6_family = AF_INET6;
					memcpy((void*)&order_in6.sin6_addr, order, 16);
					memcpy((void*)&order_in6.sin6_port, order + 16, 2);
					to = (sockaddr*)&order_in6;
					to_len = sizeof(order_in6);
				}

				if (st) {
					debugf(D, "Sending found %s peers.\n",
						from->sa_family == AF_INET6 ? " IPv6" : "");
					send_closest_nodes(D, to, to_len,
						tid, tid_len,
						info_hash, want,
						from->sa_family, st,
						token, TOKEN_SIZE);
				}else {
					debugf(D, "Sending nodes for get_peers.\n");
					send_closest_nodes(D, to, to_len,
						tid, tid_len, info_hash, want,
						0, NULL, token, TOKEN_SIZE);
				}

				node* n = neighbourhoodup(D, D->myid, to->sa_family == AF_INET ? &D->routetable : &D->routetable6);

				///It is necessary to send 3 times continuously to detect the non arrival rate
				if (++isequence <= MAXGETPEER && n){
					send_get_peers(D, n->ss.ss_family == AF_INET ? (struct sockaddr*)&order_in : (struct sockaddr*)&order_in6,
						n->ss.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
						(struct sockaddr*)&n->ss, n->sslen, tid, 4, info_hash, -1,
						n->reply_time >= D->now.tv_sec - 15, isequence);
				}
			}
		}
		else if (memcmp(q_return, "search", q_len) == 0)
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

			debugf(D, "search!\n");
			debugf_hex(D, "tid:", tid, tid_len);
			new_node(D, id, from, fromlen, 1);
			if (id_cmp(info_hash, zeroes) == 0) {
				debugf(D, "Eek!  Got get_peers with no info_hash.\n");
				send_error(D, from, fromlen, tid, tid_len,
					203, "search with no info_hash");
				return;
			}
			else {
				unsigned char token[TOKEN_SIZE];
				make_token(D, from, 0, token);

				debugf(D, "Sending nodes for search.\n");
				send_closest_nodes(D, from, fromlen,
					tid, tid_len, info_hash, want,
					0, NULL, token, TOKEN_SIZE);			
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

			unsigned char* order;
			int order_len;
			b_find(a, "order", &order, order_len);
			if (order_len == 0)
				goto dontread;

			unsigned char* sequence;
			int sequence_len;
			b_find(a, "sequence", &sequence, sequence_len);
			if (sequence_len == 0)
				goto dontread;
			int isequence = -1;
			memcpy(&isequence, sequence, sequence_len);
			if (isequence == -1)
				goto dontread;

			unsigned char* value;
			int value_len;
			b_find(a, "value", &value, value_len);
			if (value_len == 0)
				goto dontread;

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
			if (value_len == 0) {
				debugf(D, "Announce_peer with forbidden port %d.\n", value_len);
				send_error(D, from, fromlen, tid, tid_len,
					203, "Announce_peer with forbidden port number");
				return;
			}
			storage_store(D, info_hash, (const char*)value, value_len);
			/* Note that if storage_store failed, we lie to the requestor.
			This is to prevent them from backtracking, and hence
			polluting the DHT. */

			struct sockaddr_in order_in;
			struct sockaddr_in6 order_in6;
			struct sockaddr* to;
			int to_len;
			if (order_len == 6){
				order_in.sin_family = AF_INET;
				memcpy((void*)&order_in.sin_addr, order, 4);
				memcpy((void*)&order_in.sin_port, order+4, 2);
				to = (sockaddr*)&order_in;
				to_len = sizeof(order_in);
			}else if (order_len == 18){
				order_in6.sin6_family = AF_INET6;
				memcpy((void*)&order_in6.sin6_addr, order, 16);
				memcpy((void*)&order_in6.sin6_port, order + 16, 2);
				to = (sockaddr*)&order_in6;
				to_len = sizeof(order_in6);
			}

			debugf(D, "Sending peer announced.\n");
			send_peer_announced(D, to, to_len, tid, tid_len);

			///选择一个最近的临近节点将消息转发给他
			node* n = neighbourhoodup(D, D->myid, to->sa_family == AF_INET ? &D->routetable : &D->routetable6);

			///It is necessary to send 3 times continuously to detect the non arrival rate
			if (++isequence <= MAXANNOUNCE && n){
				send_announce_peer(D, n->ss.ss_family == AF_INET ? (struct sockaddr*)&order_in : (struct sockaddr*)&order_in6,
					n->ss.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
					(struct sockaddr*)&n->ss,
					sizeof(struct sockaddr_storage),
					tid, 4, info_hash, IDLEN,
					(unsigned char*)value, value_len,
					token, token_len,
					n->reply_time >= D->now.tv_sec - 15, isequence);
			}
		}

		if (!token_bucket(D)) {
			debugf(D, "Dropping request due to rate limiting.\n");
		}
	}
	return;

dontread:
	debugf(D, "Unparseable message: ");
	debug_printable(D, (unsigned char *)buf, buflen);
	debugf(D, "\n");
}