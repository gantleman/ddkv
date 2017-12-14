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
#include <set>

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
#include "whiteboard.h"

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
	time_t pinged_time;         /* time of last request */
	int pinged;                 /* how many requests we sent since last reply */
	std::vector<unsigned char> syn_key;/*Syn data for the first landing,recode laste key*/
	time_t syn_time;/*last syn tiem*/
	std::vector<unsigned char> sync_key;/*Sync data for the first landing,recode laste key*/
	time_t sync_time;/*last sync tiem*/
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

#define MAXGETPEER   1
#define MAXANNOUNCE  3

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
	std::list<gp_node> gpnode;//already return node, announce peer user too
	std::map<std::vector<char>, int> gpresult;//Return result ranking
};

struct peer {
	//Each node of the routing table can judge whether it is the head or tail of the data.
	time_t time;
	std::vector<char> buf;     //data block
};

/* The maximum number of searches we keep data about. */
#ifndef DHT_MAX_SEARCHES
#define DHT_MAX_SEARCHES 1024
#endif

/* The time after which we consider a search to be expirable. */
#ifndef DHT_SEARCH_EXPIRE_TIME
#define DHT_SEARCH_EXPIRE_TIME (62 * 60)
#endif

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
	unsigned char v[4];
	unsigned char secret[8];
	unsigned char oldsecret[8];

	std::map<std::vector<unsigned char>, peer> storage;

	struct search *searches;
	int numsearches;
	unsigned short search_id;

	struct sockaddr_storage blacklist[DHT_MAX_BLACKLISTED];
	int next_blacklisted;

	struct timeval now;
	time_t mybucket_grow_time, mybucket6_grow_time;
	time_t expire_stuff_time;
	time_t expire_buckets_time;

	time_t token_bucket_time;
	int token_bucket_tokens;

	FILE *dht_debug;

	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	std::map<std::vector<unsigned char>, node> routetable;
	std::map<std::vector<unsigned char>, node> routetable6;

	std::map<std::vector<unsigned char>, time_t> gossip;
	time_t gossip_expire_time;

	time_t ping_neighbourhood_time;

	//When the sender drops a line to stir up new synchronization
	std::vector<unsigned char> syn_key;
	time_t syn_time;
	std::vector<unsigned char> sync_key;
	time_t sync_time;
}*pdht, dht;

static struct peer * find_storage(pdht D, const unsigned char *id);
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
	int af, struct peer *sp,
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
static void expire_gossip(pdht D);
static void send_gossip_step(pdht D, unsigned char *gid,
	const char* buf, int len);
static node* neighbourhoodup(pdht D, const unsigned char *id,
	std::map<std::vector<unsigned char>, node> *r);
static void
send_nodedown(pdht D, const unsigned char * id, unsigned char* gid);
static void
node_ponged(pdht D, const unsigned char *id, const struct sockaddr *sa, int salen);
#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3)))
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
	unsigned char x;
	for (i = 0; i < IDLEN; i++) {
		if (id1[i] != id2[i])
			break;
	}

	if (i == IDLEN)
		return 160;

	x = id1[i] ^ id2[i];

	j = 0;
	while ((x & 0x80) == 0) {
		x <<= 1;
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
	if (iter != r->end()) {
		return &iter->second;
	}

	return NULL;
}

/* This is our definition of a known-good node. */
static int
node_good(pdht D, struct node *node)
{
	return
		node->pinged <= 2;
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
	} else
		return 0;
}

/* Called whenever we send a request to a node, increases the ping count
   and, if that reaches 3, sends a ping to a new candidate. */
static void
node_pinged(pdht D, struct node *n)
{
	n->pinged++;
	n->pinged_time = D->now.tv_sec;
}

static void
node_ponged(pdht D, const unsigned char *id, const struct sockaddr *sa, int salen)
{
	if (id_cmp(id, D->myid) == 0)
		return;

	std::map<std::vector<unsigned char>, node> *r = sa->sa_family == AF_INET ? &D->routetable : &D->routetable6;
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);

	std::map<std::vector<unsigned char>, node>::iterator iter = r->find(k);
	if (iter != r->end()) {
		struct node *n = &iter->second;
		n->pinged = 0;
		n->pinged_time = 0;
	} 
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
			node_pinged(D, n);
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
	if (iter == r->end()) {
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
		n->pinged = 0;
		n->pinged_time = D->now.tv_sec;
		return n;
	}
	return 0;
}

static int
del_node(pdht D, const unsigned char *id, int af)
{
	std::map<std::vector<unsigned char>, node> *r = af == AF_INET ? &D->routetable : &D->routetable6;
	std::vector<unsigned char> k, myk;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);
	myk.resize(IDLEN);
	memcpy(&myk[0], D->myid, IDLEN);

	std::map<std::vector<unsigned char>, node>::iterator itercur, iter = r->find(k);
	itercur = iter;
	itercur--;
	int pos = -1;
	if (iter != r->end()) {
		for (;;) {
			if (itercur == r->end()) {
				itercur--;
				continue;
			}
			if (++pos >= MAXGETPEER || itercur->first == myk) {
				pos = -1;
				break;
			}
			if (itercur->first == myk) {
				break;
			}
		}
		r->erase(iter);
	}
	return pos;
}

/* Called periodically to purge known-bad nodes.  Note that we're very
   conservative here: broken nodes in the table don't do much harm, we'll
   recover as soon as we find better ones. */
static int
expire_buckets(pdht D, std::map<std::vector<unsigned char>, node> *routetable)
{
	std::map<std::vector<unsigned char>, node>::iterator iter = routetable->begin();
	for (; iter != routetable->end();) {
		if (iter->second.pinged >= 3 && D->now.tv_sec - iter->second.pinged_time > 2) {
			send_nodedown(D, iter->second.id, 0);
		} else if (iter->second.pinged >= 3 && D->now.tv_sec - iter->second.pinged_time > 20*60) {
			iter = routetable->erase(iter);
		} else
			iter++;
	}

	D->expire_buckets_time = D->now.tv_sec + random() % 10;
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
		} else {
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
		} else {
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
	if (node) node_pinged(D, node);
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
			if (!sr->getpeer) {
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
					debugf(D, "Sending get peers.\n");
					make_tid(tid, "gp", sr->tid);
					debugf_hex(D, "tid:", tid, 4);
					send_get_peers(D, n->ss.ss_family == AF_INET ? (struct sockaddr*)&D->sin : (struct sockaddr*) &D->sin6,
						n->ss.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
						(struct sockaddr*)&n->ss, n->sslen, tid, 4, sr->id, -1,
						n->reply_time >= D->now.tv_sec - 15, 0);

					n->pinged++;
					n->request_time = D->now.tv_sec;
					node = find_node(D, n->id, n->ss.ss_family);
					if (node) node_pinged(D, node);
					break;
				}
				if (!sendap) {
					debugf(D, "Sending get peers error.\n");
				}
			} else if (sr->gpnode.size() < MAXGETPEER && D->now.tv_sec - sr->step_time > 60) {
				///outtime try again
			} else if (sr->gpnode.size() >= MAXGETPEER) {
				goto done;
			}

		} else {
			///begin step announce peer
			if (!sr->getpeer) {
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
					debugf(D, "Sending announce peer.\n");
					make_tid(tid, "ap", sr->tid);
					send_announce_peer(D, n->ss.ss_family == AF_INET ? (struct sockaddr*)&D->sin : (struct sockaddr*)&D->sin6,
						n->ss.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
						(struct sockaddr*)&n->ss,
						n->sslen,
						tid, 4, sr->id, IDLEN,
						(unsigned char*)&sr->buf[0], sr->buf.size(),
						n->token, n->token_len,
						n->reply_time >= D->now.tv_sec - 15, 0);
					n->pinged++;
					n->request_time = D->now.tv_sec;
					node = find_node(D, n->id, n->ss.ss_family);
					if (node) node_pinged(D, node);
					break;
				}
				if (!sendap) {
					debugf(D, "Sending announce peer error.\n");
				}
			} else if (sr->gpnode.size() < MAXANNOUNCE && D->now.tv_sec - sr->step_time > 60) {
				///outtime try again
			} else if (sr->gpnode.size() >= MAXANNOUNCE) {
				debugf(D, "Sending search successfully.\n");
				if (sr->callback)
					(*sr->callback)((DHT)D, sr->closure,
					sr->af == AF_INET ? DHT_EVENT_SEARCH_DONE : DHT_EVENT_SEARCH_DONE6,
					sr->id, NULL, 0);
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
		debugf(D, "Sending search.\n");
		j += search_send(D, sr, &sr->nodes[i]);
		if (j >= 3)
			break;
	}
	sr->step_time = D->now.tv_sec;
	return;

done:
	debugf(D, "search step %d done.\n", sr->tid);
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
		sr = new search;
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
	for (; iter != r->end(); iter++) {
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
	if (pg && len) {
		sr->buf.resize(len);
		memcpy(&sr->buf[0], buf, len);
	}

	insert_search_bucket(D, sr);

	search_step(D, sr);
	D->search_time = D->now.tv_sec;
	return sr->tid;
}

static peer*
enum_storage(pdht D, const unsigned char *mid, const unsigned char *up, const unsigned char *down, unsigned char *info_id,
const unsigned char** outkey)
{
	std::vector<unsigned char> k;
	std::map<std::vector<unsigned char>, peer>::iterator iter;
	if (info_id == 0)
	{
		k.resize(IDLEN);
		memcpy(&k[0], info_id, IDLEN);
		iter = D->storage.upper_bound(k);
	} else {
		iter = D->storage.begin();
	}	

	for (; iter!=D->storage.end(); iter++)
	{
		if (xorcmp(mid, up, &iter->first[0]) < 0 && xorcmp(mid, down, &iter->first[0]) < 0) {
			*outkey = &iter->first[0];
			return &iter->second;
		}
	}

	return 0;
}

static peer*
enum_storage(pdht D, unsigned char *info_id,
const unsigned char** outkey, std::vector<node*> &v)
{
	std::vector<unsigned char> k;
	std::map<std::vector<unsigned char>, peer>::iterator iter;
	if (info_id == 0) {
		k.resize(IDLEN);
		memcpy(&k[0], info_id, IDLEN);
		iter = D->storage.upper_bound(k);
	} else {
		iter = D->storage.begin();
	}

	for (; iter != D->storage.end(); iter++) {
		for (int i = 1; i <= MAXANNOUNCE; i++)
		{
			if (xorcmp(v[i]->id, v[i - 1]->id, &iter->first[0]) < 0 && xorcmp(v[i]->id, v[i + 1]->id, &iter->first[0]) < 0) {
				*outkey = &iter->first[0];
				return &iter->second;
			}
		}
	}
	return 0;
}


/* A struct storage stores all the stored peer addresses for a given info
   hash. */
static struct peer *
find_storage(pdht D, const unsigned char *id)
{
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);
	std::map<std::vector<unsigned char>, peer>::iterator iter = D->storage.find(k);
	if (iter != D->storage.end()) {
		return &iter->second;
	}
	return 0;
}

static int
storage_store(pdht D, const unsigned char *id,
const char* buf, int len)
{
	struct peer *sp;
	sp = find_storage(D, id);
	if (sp == NULL) {
		std::vector<unsigned char> k;
		k.resize(IDLEN);
		memcpy(&k[0], id, IDLEN);
		sp = &D->storage[k];
	}

	sp->time = D->now.tv_sec;
	sp->buf.resize(len);
	memcpy(&sp->buf[0], buf, len);
	return 1;
}

static int
expire_storage(pdht D)
{
	debugf(D, "expire_storage.\n");
	std::map<std::vector<unsigned char>, peer>::iterator iter = D->storage.begin();
	for (; iter != D->storage.end();) {
		if (iter->second.time < D->now.tv_sec - 32 * 60) {
			iter = D->storage.erase(iter);
		} else
			iter++;
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
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
		ip = &sin6->sin6_addr;
		iplen = 16;
		port = htons(sin6->sin6_port);
	} else {
		abort();
	}

	dht_hash(token_return, TOKEN_SIZE,
		old ? D->oldsecret : D->secret, sizeof(D->secret),
		ip, iplen, (unsigned char*)&port, 2);
}

int
dht_nodes(DHT iD, int af, int *good_return, int *dubious_return,
int *incoming_return)
{
	pdht D = (pdht)iD;
	debugf(D, "dht_nodes.\n");
	int good = 0, dubious = 0;
	std::map<std::vector<unsigned char>, node> *r = af == AF_INET ? &D->routetable : &D->routetable6;
	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	for (; iter != r->end(); iter++) {
		node *n = &iter->second;
		if (node_good(D, n)) {
			good++;
		} else {
			dubious++;
		}
	}

	if (good_return)
		*good_return = good;
	if (dubious_return)
		*dubious_return = dubious;
	return good + dubious;
}

static void
dump_bucket(pdht D, FILE *f, std::map<std::vector<unsigned char>, node> *r)
{
	fprintf(f, "rount ");
	fprintf(f, " count %d :\n",
		r->size());

	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	for (; iter != r->end(); iter++) {
		node* n = &iter->second;
		char buf[512];
		unsigned short port;
		fprintf(f, "    Node ");
		print_hex(f, n->id, IDLEN);
		if (n->ss.ss_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in*)&n->ss;
			inet_ntop(AF_INET, &sin->sin_addr, buf, 512);
			port = ntohs(sin->sin_port);
		} else if (n->ss.ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
			inet_ntop(AF_INET6, &sin6->sin6_addr, buf, 512);
			port = ntohs(sin6->sin6_port);
		} else {
			snprintf(buf, 512, "unknown(%d)", n->ss.ss_family);
			port = 0;
		}

		if (n->ss.ss_family == AF_INET6)
			fprintf(f, " [%s]:%d ", buf, port);
		else
			fprintf(f, " %s:%d ", buf, port);
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
	std::map<std::vector<unsigned char>, peer>::iterator iter = D->storage.begin();
	for (; iter != D->storage.end();) {
		struct peer* sp = &iter->second;
		fprintf(f, "\nStorage ");
		print_hex(f, &iter->first[0], IDLEN);

		fprintf(f, "[");
		print_hex(f, (unsigned char*)&sp->buf[0], sp->buf.size());
		fprintf(f, "](%ld)", (long)(D->now.tv_sec - sp->time));
	}

	fprintf(f, "\n\n");
	fflush(f);
}

int
dht_init(DHT* OutD, int s, int s6, const unsigned char *id,
const unsigned char *v, FILE* df,
struct sockaddr_in &sin, struct sockaddr_in6 &sin6)
{
	int rc;
	pdht D = new dht;
	*OutD = D;
	D->dht_debug = df;

	D->searches = NULL;
	D->numsearches = 0;
	D->gossip_expire_time = 0;
	D->expire_stuff_time = 0;
	D->expire_buckets_time = 0;
	D->ping_neighbourhood_time = 0;

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
	memcpy(D->v, v, 4);
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
///The current K barrels, a barrel of K, or near the node of a barrel of K search
static int
neighbourhood_maintenance(pdht D, int af)
{
	std::map<std::vector<unsigned char>, node> *r = af == AF_INET ? &D->routetable : &D->routetable6;
	if (0 == r->size())
		return 0;

	std::map<std::vector<unsigned char>, node>::iterator iter = r->begin();
	int ir = random() % r->size();

	for (int i = 0; iter != r->end(), i < ir; iter++, i++) {}
	node* n = &iter->second;
	if (n) {
		int want = D->dht_socket >= 0 && D->dht_socket6 >= 0 ? (WANT4 | WANT6) : -1;
		unsigned char tid[4];
		debugf(D, "Sending find_node for%s neighborhood maintenance.\n",
			af == AF_INET6 ? " IPv6" : "");
		make_tid(tid, "fn", 0);
		send_find_node(D, (struct sockaddr*)&n->ss, n->sslen,
			tid, 4, D->myid, want,
			0);
		node_pinged(D, n);
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

	for (int i = 0; iter != r->end(), i < ir; iter++, i++) {}
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
			0);
		node_pinged(D, n);
		/* In order to avoid sending queries back-to-back,
		give up for now and reschedule us soon. */
		return 1;
	}
	return 0;
}

static node* neighbourhoodup(pdht D, const unsigned char *id,
	std::map<std::vector<unsigned char>, node> *r)
{
	if (r->empty())
		return 0;

	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);
	std::map<std::vector<unsigned char>, node>::iterator iter = r->lower_bound(k);
	--iter;
	for (int i = 0; i < int(r->size() + 1); i++) {
		if (iter == r->end()) {
			iter--;
			continue;
		}
		struct node *n = &iter->second;
		if (node_good(D, n)) {
			return n;
		}
		iter--;
	}
	return 0;
}

static int neighbourhooddown(pdht D, const unsigned char *id,
	std::map<std::vector<unsigned char>, node> *r, std::vector<node*> &v, int distance)
{
	if (r->empty())
		return 0;

	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);
	std::map<std::vector<unsigned char>, node>::iterator iter = r->lower_bound(k);
	++iter;
	int loop = 0;
	v.resize(distance);
	for (; loop < distance; loop++) {
		if (iter == r->end()) {
			iter++;
			continue;
		}
		struct node *n = &iter->second;
		if (node_good(D, n)) {
			loop++;
			v[loop]=n;
		}
		iter++;
	}
	return 0;
}

static node* neighbourhooddown(pdht D, const unsigned char *id,
	std::map<std::vector<unsigned char>, node> *r)
{
	if (r->empty())
		return 0;

	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], id, IDLEN);
	std::map<std::vector<unsigned char>, node>::iterator iter = r->lower_bound(k);
	++iter;
	for (int i = 0; i < int(r->size() + 1); i++) {
		if (iter == r->end()) {
			iter++;
			continue;
		}
		struct node *n = &iter->second;
		if (node_good(D, n)) {
			return n;
		}
		iter++;
	}
	return 0;
}

static int neighbourhooddown_distance(pdht D, const unsigned char *id,
	std::map<std::vector<unsigned char>, node> *r, int distance)
{
	if (r->empty())
		return 0;

	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], D->myid, IDLEN);
	std::map<std::vector<unsigned char>, node>::iterator iter = r->lower_bound(k);
	++iter;
	int loop = 0;
	for (int i = 0; i < int(r->size() + 1); i++) {
		if (iter == r->end()) {
			iter++;
			continue;
		} 
		struct node *n = &iter->second;
		if (id_cmp(id, n->id) == 0) {
			return 1;
		}
		iter++;
		if (loop++ > distance)
			return 0;
	}
	return 0;
}

int
dht_periodic(DHT iD, const void *buf, size_t buflen,
const struct sockaddr *from, int fromlen,
time_t *tosleep)
{
	pdht D = (pdht)iD;
	///Time first is fixed in one second without considering optimization
	*tosleep = 1;
	dht_gettimeofday(&D->now, NULL);

	if (buflen > 0) {
		if (!is_martian(D, from) || !node_blacklisted(D, from, fromlen)) {
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

	if (D->now.tv_sec >= D->expire_buckets_time) {
		expire_buckets(D, &D->routetable);
		expire_buckets(D, &D->routetable6);
	}

	if (D->now.tv_sec - D->expire_stuff_time > 30 * 60) {
		D->expire_stuff_time = D->now.tv_sec;
		expire_storage(D);
		expire_searches(D);
	}

	if (D->search_time > 0 && D->now.tv_sec >= D->search_time) {
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

	if (D->now.tv_sec - D->gossip_expire_time > 10 * 60 || D->gossip.size() > 100) {
		D->gossip_expire_time = D->now.tv_sec;
		expire_gossip(D);
	}

	if (D->now.tv_sec - D->ping_neighbourhood_time > 1) {
		D->ping_neighbourhood_time = D->now.tv_sec;
		node* n = neighbourhoodup(D, D->myid, &D->routetable);
		if (n) {
			node_pinged(D, n);
			dht_ping_node(D, (const struct sockaddr *)&n->ss, n->sslen);
		}

		n = neighbourhoodup(D, D->myid, &D->routetable6);
		if (n) {
			node_pinged(D, n);
			dht_ping_node(D, (const struct sockaddr *)&n->ss, n->sslen);
		}
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
	for (; iter != r->end(); iter++) {
		node* n = &iter->second;
		if (i <= *num) {
			if (node_good(D, n)) {
				sin[i++] = *(struct sockaddr_in*)&n->ss;
			}
		} else
			break;

	}

	r = &D->routetable6;
	int j = 0;
	for (; iter != r->end(); iter++) {
		node* n = &iter->second;
		if (j <= *num6) {
			if (node_good(D, n) && j <= *num6) {
				sin6[j++] = *(struct sockaddr_in6*)&n->ss;
			}
		} else
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

	if (salen == 0) {
		debugf(D, "error send salen is 0!\n");
		abort();
	}
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
		debugf(D, "EAFNOSUPPORT\n");
		errno = EAFNOSUPPORT;
		return -1;
	}

	return sendto(s, (char *)buf, len, flags, sa, salen);
}

void
send_nodeup(pdht D, const unsigned char * id, unsigned char* gid)
{
	unsigned char tid[4];
	unsigned char mgid[IDLEN];
	dht_random_bytes(mgid, IDLEN);

	make_tid(tid, "np", 0);
	b_element out, *a;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, 4);
	b_insert(&out, "q", (unsigned char*)"nodeup", 6);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	if (gid){
		b_insert(a, "g", (unsigned char*)gid, IDLEN);
	} else {
		b_insert(a, "g", (unsigned char*)mgid, IDLEN);
	}
	b_insert(a, "n", (unsigned char*)id, IDLEN);
	b_package(&out, so);

	send_gossip_step(D, gid, so.c_str(), so.size());
}

static void
send_nodedown(pdht D, const unsigned char * id, unsigned char* gid)
{
	unsigned char tid[4];
	unsigned char mgid[IDLEN];
	dht_random_bytes(mgid, IDLEN);

	make_tid(tid, "nd", 0);
	b_element out, *a;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, 4);
	b_insert(&out, "q", (unsigned char*)"nodedown", 8);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	if (gid) {
		b_insert(a, "g", (unsigned char*)gid, IDLEN);
	} else {
		b_insert(a, "g", (unsigned char*)mgid, IDLEN);
	}
	b_insert(a, "n", (unsigned char*)id, IDLEN);
	b_package(&out, so);

	send_gossip_step(D, gid, so.c_str(), so.size());
}

int
send_syn(pdht D, const struct sockaddr *sa, int salen,
unsigned char *infohash,
unsigned char *value, int value_len)
{
	unsigned char tid[4];
	unsigned char gid[IDLEN];
	dht_random_bytes(gid, IDLEN);

	make_tid(tid, "sy", 0);
	b_element out, *a;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, 4);
	b_insert(&out, "q", (unsigned char*)"syn", 3);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	b_insert(a, "info_hash", (unsigned char*)infohash, IDLEN);
	b_insert(a, "value", value, value_len);
	b_package(&out, so);

	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

int
send_synr(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len)
{
	b_element out, *r;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"r", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "r", &r);
	b_insert(r, "id", D->myid, IDLEN);
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

int
send_sync(pdht D, const struct sockaddr *sa, int salen,
unsigned char *infohash,
unsigned char *value, int value_len)
{
	unsigned char tid[4];
	unsigned char gid[IDLEN];
	dht_random_bytes(gid, IDLEN);

	make_tid(tid, "sc", 0);
	b_element out, *a;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, 4);
	b_insert(&out, "q", (unsigned char*)"sync", 4);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	b_insert(a, "info_hash", (unsigned char*)infohash, IDLEN);
	b_insert(a, "value", value, value_len);
	b_package(&out, so);

	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

int
send_syncr(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len)
{
	b_element out, *r;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"r", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "r", &r);
	b_insert(r, "id", D->myid, IDLEN);
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

int
send_ping(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len)
{
	b_element out, *a;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "q", (unsigned char*)"ping", 4);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

int
send_pong(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len)
{
	b_element out, *r;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"r", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "r", &r);
	b_insert(r, "id", D->myid, IDLEN);
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

int
send_nodes_peers(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len,
const unsigned char *nodes, int nodes_len,
const unsigned char *nodes6, int nodes6_len,
int af, struct peer *sp,
const unsigned char *token, int token_len)
{
	b_element out, *r;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"r", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "r", &r);
	b_insert(r, "id", D->myid, IDLEN);
	if (nodes_len > 0)
		b_insert(r, "nodes", (unsigned char*)nodes, nodes_len);
	if (nodes6_len > 0)
		b_insert(r, "nodes6", (unsigned char*)nodes6, nodes6_len);
	if (token_len > 0)
		b_insert(r, "token", (unsigned char*)token, token_len);
	if (sp)
		b_insert(r, "value", (unsigned char*)&sp->buf[0], sp->buf.size());
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

int
send_find_node(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len,
const unsigned char *target, int want, int confirm)
{
	b_element out, *a, *l;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "q", (unsigned char*)"find_node", 9);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	b_insert(a, "target", (unsigned char*)target, IDLEN);
	if (want > 0) {
		b_insertl(a, "want", &l);
		b_insert(l, "", (want & WANT4) ? (unsigned char*)"n4" : (unsigned char*)"", (want & WANT4) ? 2 : 0);
		b_insert(l, "", (want & WANT4) ? (unsigned char*)"n6" : (unsigned char*)"", (want & WANT6) ? 2 : 0);
	}
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), confirm ? MSG_CONFIRM : 0, sa, salen);
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
	} else if (n->ss.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&n->ss;
		memcpy(nodes + size * i, n->id, IDLEN);
		memcpy(nodes + size * i + IDLEN, &sin6->sin6_addr, 16);
		memcpy(nodes + size * i + 36, &sin6->sin6_port, 2);
	} else {
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
	for (int i = 0; iter != r->end() && i < 8; iter--) {
		struct node *n = &iter->second;
		if (node_good(D, n)) {
			i++;
			numnodes = insert_closest_node(nodes, numnodes, id, n);
		}


	}

	for (int i = 0; iter2 != r->end() && i < 8; iter2++) {
		struct node *n = &iter2->second;
		if (node_good(D, n)) {
			i++;
			numnodes = insert_closest_node(nodes, numnodes, id, n);
		}

	}
	return numnodes;
}

int
send_closest_nodes(pdht D, const struct sockaddr *sa, int salen,
const unsigned char *tid, int tid_len,
const unsigned char *id, int want,
int af, struct peer *sp,
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
		af, sp, token, token_len);
}

int
send_search(pdht D, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len, unsigned char *infohash,
int want, int confirm)
{
	b_element out, *a, *l;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "q", (unsigned char*)"search", 9);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	b_insert(a, "info_hash", (unsigned char*)infohash, IDLEN);
	if (want > 0) {
		b_insertl(a, "want", &l);
		b_insert(l, "", (want & WANT4) ? (unsigned char*)"n4" : (unsigned char*)"", (want & WANT4) ? 2 : 0);
		b_insert(l, "", (want & WANT4) ? (unsigned char*)"n6" : (unsigned char*)"", (want & WANT6) ? 2 : 0);
	}
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), confirm ? MSG_CONFIRM : 0, sa, salen);
}

int
send_get_peers(pdht D, const struct sockaddr *hsa, int hsalen,
const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len, unsigned char *infohash,
int want, int confirm, int sequence)
{
	b_element out, *a, *l;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "q", (unsigned char*)"get_peers", 9);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	b_insert(a, "info_hash", (unsigned char*)infohash, IDLEN);
	if (hsa->sa_family == AF_INET) {
		unsigned char buf[512];
		sockaddr_in* sd_in = (sockaddr_in*)hsa;
		memcpy(buf, &sd_in->sin_addr, 16);
		memcpy(buf + 4, &sd_in->sin_port, 2);
		b_insert(a, "order", buf, 6);
	} else {
		unsigned char buf[512];
		sockaddr_in6* sd_in = (sockaddr_in6*)hsa;
		memcpy(buf, &sd_in->sin6_addr, 4);
		memcpy(buf + 16, &sd_in->sin6_port, 2);
		b_insert(a, "order", buf, 6);
	}
	if (want > 0) {
		b_insertl(a, "want", &l);
		b_insert(l, "", (want & WANT4) ? (unsigned char*)"n4" : (unsigned char*)"", (want & WANT4) ? 2 : 0);
		b_insert(l, "", (want & WANT4) ? (unsigned char*)"n6" : (unsigned char*)"", (want & WANT6) ? 2 : 0);
	}
	b_insert(a, "sequence", (unsigned char*)&sequence, sizeof(int));
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), confirm ? MSG_CONFIRM : 0, sa, salen);
}

static int
send_announce_peer(pdht D, const struct sockaddr* hsa, int hsalen, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len,
unsigned char *info_hash, int info_hash_len,
unsigned char *value, int value_len,
unsigned char *token, int token_len, int confirm, int sequence)
{
	b_element out, *a;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"q", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "q", (unsigned char*)"announce_peer", 13);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "a", &a);
	b_insert(a, "id", D->myid, IDLEN);
	b_insert(a, "info_hash", (unsigned char*)info_hash, IDLEN);
	if (hsa->sa_family == AF_INET) {
		unsigned char buf[512];
		sockaddr_in* sd_in = (sockaddr_in*)hsa;
		memcpy(buf, &sd_in->sin_addr, 4);
		memcpy(buf + 4, &sd_in->sin_port, 2);
		b_insert(a, "order", buf, 6);
	} else {
		unsigned char buf[512];
		sockaddr_in6* sd_in = (sockaddr_in6*)hsa;
		memcpy(buf, &sd_in->sin6_addr, 16);
		memcpy(buf + 16, &sd_in->sin6_port, 2);
		b_insert(a, "order", buf, 18);
	}
	b_insert(a, "value", (unsigned char*)value, value_len);
	b_insert(a, "token", (unsigned char*)token, token_len);
	b_insert(a, "sequence", (unsigned char*)&sequence, sizeof(int));
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), confirm ? 0 : MSG_CONFIRM, sa, salen);
}

static int
send_peer_announced(pdht D, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len)
{
	b_element out, *r;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"r", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertd(&out, "r", &r);
	b_insert(r, "id", D->myid, IDLEN);
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

static int
send_error(pdht D, const struct sockaddr *sa, int salen,
unsigned char *tid, int tid_len,
int code, const char *message)
{
	int message_len = strlen(message);
	b_element out, *e;
	std::string so;
	b_insert(&out, "y", (unsigned char*)"e", 1);
	b_insert(&out, "t", (unsigned char*)tid, tid_len);
	b_insert(&out, "v", D->v, sizeof(D->v));
	b_insertl(&out, "e", &e);
	b_insert(e, "", (unsigned char*)&code, sizeof(int));
	b_insert(e, "", (unsigned char*)message, message_len);
	b_package(&out, so);
	return dht_send(D, so.c_str(), so.size(), 0, sa, salen);
}

static int
is_gossip(pdht D, unsigned char *gid)
{
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], gid, IDLEN);

	std::map<std::vector<unsigned char>, time_t>::iterator iterg = D->gossip.find(k);
	if (iterg == D->gossip.end())
		return 0;
	return 1;
}

static void
send_gossip_step(pdht D, unsigned char *gid, const char* buf, int len)
{
	debugf(D, "send gossip step.");
	std::vector<unsigned char> k;
	k.resize(IDLEN);
	memcpy(&k[0], gid, IDLEN);

	std::map<std::vector<unsigned char>, time_t>::iterator iterg = D->gossip.find(k);
	if (iterg == D->gossip.end())
		return;

	D->gossip[k] = D->now.tv_sec;
	std::map<std::vector<unsigned char>, node>::iterator iter = D->routetable.begin();
	for (; iter != D->routetable.end(); iter++) {
		dht_send(D, buf, len, 0, (const sockaddr *)&iter->second.ss, iter->second.sslen);
	}
	std::map<std::vector<unsigned char>, node>::iterator iter6 = D->routetable6.begin();
	for (; iter6 != D->routetable.end(); iter6++) {
		dht_send(D, buf, len, 0, (const sockaddr *)&iter6->second.ss, iter6->second.sslen);
	}
}

static void
expire_gossip(pdht D)
{
	debugf(D, "expire gossip.");
	std::map<std::vector<unsigned char>, time_t>::iterator iterg = D->gossip.begin();
	for (; iterg != D->gossip.end();) {
		if (D->now.tv_sec - iterg->second > 10 * 60) {
			iterg = D->gossip.erase(iterg);
		} else
			iterg++;
	}
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

	if (y_return[0] == 'r') {
		b_element* r;
		b_find(&e, "r", &r);
		if (r == 0)
			goto dontread;

		unsigned char *id;
		int id_len;
		b_find(r, "id", &id, id_len);
		if (id_len == 0)
			goto dontread;

		node_ponged(D, id, from, fromlen);
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
		} else if (tid_match(tid, "gp", NULL)) {
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
			} else if (gp && sr == NULL) {
				debugf(D, "Unknown search!\n");
			} else {
				int i;
				for (i = 0; i < nodes_len / 26; i++) {
					unsigned char *ni = nodes + i * 26;
					struct sockaddr_in sin;
					if (id_cmp(ni, D->myid) == 0)
						continue;
					memset(&sin, 0, sizeof(sin));
					sin.sin_family = AF_INET;
					memcpy(&sin.sin_addr, ni + IDLEN, 4);
					memcpy(&sin.sin_port, ni + 24, 2);
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
					if (sr && sr->af == AF_INET6) {
						insert_search_node(D, ni,
							(struct sockaddr*)&sin6,
							sizeof(sin6),
							sr, 0, NULL, 0);
					}
				}
			}
			if (sr) {
				debugf(D, "analysis get peer!\n");
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
				if (value_len != 0) {
					gp_node n;
					memcpy(&n.ss, &from, fromlen);
					n.sslen = fromlen;
					sr->gpnode.push_back(n);
					if (sr->callback) {
						if (value_len > 0)
							(*sr->callback)((DHT)D, sr->closure, DHT_EVENT_VALUES, sr->id,
							(void*)value, value_len);
					}
				} else {
					(*sr->callback)((DHT)D, sr->closure, DHT_EVENT_VALUES, sr->id,
						(void*)0, 0);
				}
			}
		} else if (tid_match(tid, "sr", NULL)) {
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
			} else if (sh && sr == NULL) {
				debugf(D, "Unknown search!\n");
			} else {
				int i;
				for (i = 0; i < nodes_len / 26; i++) {
					unsigned char *ni = nodes + i * 26;
					struct sockaddr_in sin;
					if (id_cmp(ni, D->myid) == 0)
						continue;
					memset(&sin, 0, sizeof(sin));
					sin.sin_family = AF_INET;
					memcpy(&sin.sin_addr, ni + IDLEN, 4);
					memcpy(&sin.sin_port, ni + 24, 2);
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
		} else if (tid_match(tid, "fn", NULL)) {
			unsigned char *nodes, *nodes6;
			int nodes_len, nodes6_len;
			b_find(r, "nodes", &nodes, nodes_len);
			b_find(r, "nodes6", &nodes6, nodes6_len);

			if (nodes_len % 26 != 0 || nodes6_len % 38 != 0) {
				debugf(D, "Unexpected length for node info!\n");
				blacklist_node(D, id, from, fromlen);
			} else {
				int i;
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
		} else if (tid_match(tid, "ap", &ttid)) {
			struct search *sr;
			debugf(D, "Got reply to announce_peer.\n");
			sr = find_search(D, ttid, from->sa_family);
			if (!sr) {
				debugf(D, "error Unknown search!\n");
			} else {
				int i;
				for (i = 0; i < sr->numnodes; i++)
					if (id_cmp(sr->nodes[i].id, id) == 0) {
						sr->nodes[i].request_time = 0;
						sr->nodes[i].reply_time = D->now.tv_sec;
						sr->nodes[i].pinged = 0;
						break;
					}

				gp_node n;
				memcpy(&n.ss, from, fromlen);
				n.sslen = fromlen;
				sr->gpnode.push_back(n);
			}
		} else if (tid_match(tid, "sc", &ttid)) {
			node * mid = find_node(D, id, from->sa_family);
			if (mid && mid->sync_key.empty())
				goto dontread;

			debugf(D, "Got reply to sync!\n");
			///return sync		
			node * up = neighbourhoodup(D, mid->id, from->sa_family == AF_INET ? &D->routetable : &D->routetable6);
			node * down = neighbourhooddown(D, mid->id, from->sa_family == AF_INET ? &D->routetable : &D->routetable6);
			const unsigned char* key;
			peer* p = enum_storage(D, mid->id, up->id, down->id, (unsigned char*)&mid->sync_key[0], &key);
			if (0 != p) {
				debugf(D, "conitiue sync!\n");
				debugf_hex(D, "key:", key, IDLEN);
				send_sync(D, from, fromlen, (unsigned char*)key, (unsigned char*)&p->buf[0], p->buf.size());
				mid->sync_key.resize(IDLEN);
				memcpy(&mid->sync_key[0], key, IDLEN);
				mid->sync_time = D->now.tv_sec;
			} else {
				debugf(D, "closure sync!\n");
				send_syn(D, from, fromlen, (unsigned char*)D->myid, (unsigned char*)0, 0);
				mid->sync_key.clear();
				mid->sync_time = D->now.tv_sec;
			}
		} else if (tid_match(tid, "sy", &ttid)) {
			node * n = find_node(D, id, from->sa_family);
			if (n && n->syn_key.empty())
				goto dontread;
			debugf(D, "Got reply to syn!\n");
			if (neighbourhooddown_distance(D, id, from->sa_family == AF_INET ? &D->routetable : &D->routetable6, MAXANNOUNCE)) {
				std::vector<node*> v;
				neighbourhooddown(D, id, from->sa_family == AF_INET ? &D->routetable : &D->routetable6, v, MAXANNOUNCE + 1);
				const unsigned char* key;
				peer* p = enum_storage(D, (unsigned char*)&n->syn_key[0], &key, v);
				if (0 != p) {
					debugf(D, "conitiue syn!\n");
					debugf_hex(D, "key:", key, IDLEN);
					send_syn(D, from, fromlen, (unsigned char*)key, (unsigned char*)&p->buf[0], p->buf.size());
					n->syn_key.resize(IDLEN);
					memcpy(&n->syn_key[0], key, IDLEN);
					n->syn_time = D->now.tv_sec;
				} else {
					debugf(D, "closure syn!\n");
					send_syn(D, from, fromlen, (unsigned char*)D->myid, (unsigned char*)0, 0);
					n->syn_key.clear();
					n->syn_time = D->now.tv_sec;
				}
			}
		}else {
			debugf(D, "Unexpected reply: ");
			debug_printable(D, (unsigned char *)buf, buflen);
			debugf(D, "\n");
		}
	} else if (y_return[0] == 'q') {
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

		if (memcmp(q_return, "ping", q_len) == 0) {
			debugf(D, "Ping (%d)!\n", tid_len);
			debugf(D, "Sending pong.\n");
			send_pong(D, from, fromlen, tid, tid_len);
		} else if (memcmp(q_return, "find_node", q_len) == 0) {
			unsigned char *target;
			int target_len;
			b_find(a, "target", &target, target_len);
			if (target_len == 0)
				goto dontread;

			int want = -1;
			b_element *e_want, *l_want;
			b_find(a, "want", &e_want);
			if (e_want != 0) {
				b_get(e_want, 0, &l_want);
				if (l_want != 0) {
					while (true) {
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
			debugf(D, "Sending closest nodes (%d).\n", want);
			send_closest_nodes(D, from, fromlen,
				tid, tid_len, target, want,
				0, NULL, NULL, 0);
		} else if (memcmp(q_return, "get_peers", q_len) == 0) {
			unsigned char *info_hash;
			int info_hash_len;
			b_find(a, "info_hash", &info_hash, info_hash_len);
			if (info_hash_len == 0)
				goto dontread;

			int want = -1;
			b_element *e_want, *l_want;
			b_find(a, "want", &e_want);
			if (e_want != 0) {
				b_get(e_want, 0, &l_want);
				if (l_want != 0) {
					while (true) {
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
			if (id_cmp(info_hash, zeroes) == 0) {
				debugf(D, "Eek!  Got get_peers with no info_hash.\n");
				send_error(D, from, fromlen, tid, tid_len,
					203, "Get_peers with no info_hash");
				return;
			} else {
				struct peer *sp = find_storage(D, info_hash);
				unsigned char token[TOKEN_SIZE];
				make_token(D, from, 0, token);

				struct sockaddr_in order_in;
				struct sockaddr_in6 order_in6;
				struct sockaddr* to;
				int to_len;
				if (order_len == 6) {
					order_in.sin_family = AF_INET;
					memcpy((void*)&order_in.sin_addr, order, 4);
					memcpy((void*)&order_in.sin_port, order + 4, 2);
					to = (sockaddr*)&order_in;
					to_len = sizeof(order_in);
				} else if (order_len == 18) {
					order_in6.sin6_family = AF_INET6;
					memcpy((void*)&order_in6.sin6_addr, order, 16);
					memcpy((void*)&order_in6.sin6_port, order + 16, 2);
					to = (sockaddr*)&order_in6;
					to_len = sizeof(order_in6);
				}

				if (sp) {
					debugf(D, "Sending found %s peers.\n",
						from->sa_family == AF_INET6 ? " IPv6" : "IPv4");
					send_closest_nodes(D, to, to_len,
						tid, tid_len,
						info_hash, want,
						from->sa_family, sp,
						token, TOKEN_SIZE);
				} else {
					node* n = neighbourhoodup(D, D->myid, to->sa_family == AF_INET ? &D->routetable : &D->routetable6);
					///It is necessary to send 3 times continuously to detect the non arrival rate
					if (++isequence <= MAXGETPEER && n) {
						debugf(D, "Sendin get_peers to next neighbourhood.\n");
						send_get_peers(D, n->ss.ss_family == AF_INET ? (struct sockaddr*)&order_in : (struct sockaddr*)&order_in6,
							n->ss.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
							(struct sockaddr*)&n->ss, n->sslen, tid, 4, info_hash, -1,
							0, isequence);
					} else {
						debugf(D, "Sending nodes for get_peers.\n");
						send_closest_nodes(D, to, to_len,
							tid, tid_len, info_hash, want,
							0, NULL, token, TOKEN_SIZE);
					}
				}
			}
		} else if (memcmp(q_return, "search", q_len) == 0) {
			unsigned char *info_hash;
			int info_hash_len;
			b_find(a, "info_hash", &info_hash, info_hash_len);
			if (info_hash_len == 0)
				goto dontread;

			int want = -1;
			b_element *e_want, *l_want;
			b_find(a, "want", &e_want);
			if (e_want != 0) {
				b_get(e_want, 0, &l_want);
				if (l_want != 0) {
					while (true) {
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
			if (id_cmp(info_hash, zeroes) == 0) {
				debugf(D, "Eek!  Got get_peers with no info_hash.\n");
				send_error(D, from, fromlen, tid, tid_len,
					203, "search with no info_hash");
				return;
			} else {
				unsigned char token[TOKEN_SIZE];
				make_token(D, from, 0, token);

				debugf(D, "Sending nodes for search.\n");
				send_closest_nodes(D, from, fromlen,
					tid, tid_len, info_hash, want,
					0, NULL, token, TOKEN_SIZE);
			}
		} else if (memcmp(q_return, "announce_peer", q_len) == 0) {
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
			if (id_cmp(info_hash, zeroes) == 0) {
				debugf(D, "error Announce_peer with no info_hash.\n");
				send_error(D, from, fromlen, tid, tid_len,
					203, "Announce_peer with no info_hash");
				return;
			}
			if (value_len == 0) {
				debugf(D, "error Announce_peer with forbidden port %d.\n", value_len);
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
			if (order_len == 6) {
				order_in.sin_family = AF_INET;
				memcpy((void*)&order_in.sin_addr, order, 4);
				memcpy((void*)&order_in.sin_port, order + 4, 2);
				to = (sockaddr*)&order_in;
				to_len = sizeof(order_in);
			} else if (order_len == 18) {
				order_in6.sin6_family = AF_INET6;
				memcpy((void*)&order_in6.sin6_addr, order, 16);
				memcpy((void*)&order_in6.sin6_port, order + 16, 2);
				to = (sockaddr*)&order_in6;
				to_len = sizeof(order_in6);
			}

			debugf(D, "Sending peer announced.\n");
			send_peer_announced(D, to, to_len, tid, tid_len);

			node* n = neighbourhoodup(D, D->myid, from->sa_family == AF_INET ? &D->routetable : &D->routetable6);
			///It is necessary to send 3 times continuously to detect the non arrival rate
			if (++isequence < MAXANNOUNCE && n) {
				unsigned short port = 0;
				if (n->ss.ss_family == AF_INET) {
					sockaddr_in* si = (sockaddr_in*)&n->ss;
					port = ntohs(si->sin_port);
				} else {
					sockaddr_in6* si = (sockaddr_in6*)&n->ss;
					port = ntohs(si->sin6_port);
				}
				debugf(D, "at %d Sending peer announced to port %d.\n", isequence, port);
				send_announce_peer(D, n->ss.ss_family == AF_INET ? (struct sockaddr*)&order_in : (struct sockaddr*)&order_in6,
					n->ss.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
					(struct sockaddr*)&n->ss,
					n->sslen,
					tid, 4, info_hash, IDLEN,
					(unsigned char*)value, value_len,
					token, token_len,
					0, isequence);
			} else
				debugf(D, "at %d not find neighbourhoodup.\n", isequence);
		} else if (memcmp(q_return, "node_up", q_len) == 0) {

			unsigned char *gid;
			int gid_len;
			b_find(a, "g", &gid, gid_len);
			if (gid_len == 0)
				goto dontread;

			unsigned char *nid;
			int nid_len;
			b_find(a, "n", &nid, nid_len);
			if (nid_len == 0)
				goto dontread;

			if (!is_gossip(D, gid)) {
				debugf(D, "revice node_up.\n");
				node* nf = new_node(D, id, from, fromlen, 2);
				debugf_hex(D, "fromid:", nf->id, IDLEN);
				node* n = neighbourhoodup(D, D->myid, from->sa_family == AF_INET ? &D->routetable : &D->routetable6);
				if (id_cmp(n->id, id) == 0 && n->sync_key.empty()) {
					if (neighbourhooddown_distance(D, id, from->sa_family == AF_INET ? &D->routetable : &D->routetable6, MAXANNOUNCE)) {
						std::vector<node*> v;
						neighbourhooddown(D, id, from->sa_family == AF_INET ? &D->routetable : &D->routetable6, v, MAXANNOUNCE + 1);
						const unsigned char* key;
						peer* p = enum_storage(D, 0, &key, v);
						if (0 != p) {
							debugf(D, "send syn to neighbourhood");
							send_syn(D, from, fromlen, (unsigned char*)key, (unsigned char*)&p->buf[0], p->buf.size());
							n->sync_key.resize(IDLEN);
							memcpy(&n->syn_key[0], key, IDLEN);
							n->syn_time = D->now.tv_sec;
							if (nf) node_pinged(D, nf);
						}
					}
				}

				n = neighbourhooddown(D, D->myid, from->sa_family == AF_INET ? &D->routetable : &D->routetable6);
				if (id_cmp(n->id, id) == 0 && n->sync_key.empty()) {
					node * down = neighbourhooddown(D, n->id, from->sa_family == AF_INET ? &D->routetable : &D->routetable6);
					const unsigned char* key;
					peer* p = enum_storage(D, id, D->myid, down->id, 0, &key);
					if (0 != p) {
						debugf(D, "send sync to neighbourhood");
						send_sync(D, from, fromlen, (unsigned char*)key, (unsigned char*)&p->buf[0], p->buf.size());
						n->sync_key.resize(IDLEN);
						memcpy(&n->sync_key[0], key, IDLEN);
						n->sync_time = D->now.tv_sec;
						if (nf) node_pinged(D, nf);
					}
				}
			}
			send_nodeup(D, nid, gid);
		} else if (memcmp(q_return, "sync", q_len) == 0) {
			debugf(D, "send sync to neighbourhood");
			unsigned char *info_hash;
			int info_hash_len;
			b_find(a, "info_hash", &info_hash, info_hash_len);
			if (info_hash_len == 0)
				goto dontread;

			unsigned char* value;
			int value_len;
			b_find(a, "value", &value, value_len);
			
			debugf(D, "sync!\n");
			if (value_len != 0) {
				debugf(D, "sync storage!\n");
				peer* p = find_storage(D, info_hash);
				if (0 == p) {				
					storage_store(D, info_hash, (char*)value, value_len);
				}
				send_syncr(D, from, fromlen, tid, tid_len);
				D->sync_key.resize(IDLEN);
				memcpy(&D->sync_key[0], info_hash, IDLEN);
				D->syn_time = D->now.tv_sec;
			} else {
				debugf(D, "sync finish!\n");
				D->sync_key.clear();
				D->syn_time = D->now.tv_sec;
			}
		} else if (memcmp(q_return, "syn", q_len) == 0) {
			unsigned char *info_hash;
			int info_hash_len;
			b_find(a, "info_hash", &info_hash, info_hash_len);
			if (info_hash_len == 0)
				goto dontread;

			unsigned char* value;
			int value_len;
			b_find(a, "value", &value, value_len);

			debugf(D, "syn!\n");			
			if (value_len != 0) {
				debugf(D, "syn storage!\n");
				storage_store(D, info_hash, (char*)value, value_len);
				send_synr(D, from, fromlen, tid, tid_len);
				D->syn_key.resize(IDLEN);
				memcpy(&D->syn_key[0], info_hash, IDLEN);
				D->syn_time = D->now.tv_sec;
			}else{
				debugf(D, "syn finish!\n");
				D->syn_key.clear();
				D->syn_time = D->now.tv_sec;
			}

		} else if (memcmp(q_return, "node_down", q_len) == 0) {

			unsigned char *gid;
			int gid_len;
			b_find(a, "g", &gid, gid_len);
			if (gid_len == 0)
				goto dontread;

			unsigned char *nid;
			int nid_len;
			b_find(a, "n", &nid, nid_len);
			if (nid_len == 0)
				goto dontread;

			if (!is_gossip(D, gid)) {
				debugf(D, "node down!\n");
				node* n = neighbourhoodup(D, D->myid, from->sa_family == AF_INET ? &D->routetable : &D->routetable6);
				n->pinged=3;
				node* sn = neighbourhoodup(D, n->id, from->sa_family == AF_INET ? &D->routetable : &D->routetable6);
				if (id_cmp(n->id, nid) == 0 && n->sync_key.empty()) {
					if (neighbourhooddown_distance(D, nid, from->sa_family == AF_INET ? &D->routetable : &D->routetable6, MAXANNOUNCE)) {
						std::vector<node*> v;
						neighbourhooddown(D, nid, from->sa_family == AF_INET ? &D->routetable : &D->routetable6, v, MAXANNOUNCE + 1);
						const unsigned char* key;
						peer* p = enum_storage(D, 0, &key, v);
						if (0 != p) {
							debugf(D, "send syn!\n");
							send_syn(D, (const struct sockaddr *)&sn->ss, sn->sslen, (unsigned char*)key, (unsigned char*)&p->buf[0], p->buf.size());
							n->sync_key.resize(IDLEN);
							memcpy(&n->syn_key[0], key, IDLEN);
							n->syn_time = D->now.tv_sec;
							if (sn) node_pinged(D, sn);
						}
					}
				}
			}
			send_nodedown(D, nid, gid);
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