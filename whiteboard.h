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

#define DHT void*

typedef void
dht_callback(DHT D,
			 void *closure, int event,
             const unsigned char *info_hash,
             const void *data, size_t data_len);

#define DHT_EVENT_NONE 0
#define DHT_EVENT_VALUES 1
#define DHT_EVENT_VALUES6 2
#define DHT_EVENT_SEARCH_DONE 3
#define DHT_EVENT_SEARCH_DONE6 4

int dht_init(DHT* D, int s, int s6, const unsigned char *id,
			const unsigned char *v, FILE* df,
			struct sockaddr_in &sin,
			struct sockaddr_in6 &sin6);
int dht_insert_node(DHT D, const unsigned char *id, struct sockaddr *sa, int salen);
int dht_ping_node(DHT D, const struct sockaddr *sa, int salen);
int dht_periodic(DHT D, const void *buf, size_t buflen,
                 const struct sockaddr *from, int fromlen,
                 time_t *tosleep);
int dht_search(DHT D, const unsigned char *id, int pg, int af,
               dht_callback *callback, void *closure, const char* buf=0, int len=0);
int dht_nodes(DHT D, int af,
              int *good_return, int *dubious_return,
              int *incoming_return);
void dht_dump_tables(DHT D, FILE *f);
int dht_get_nodes(DHT D, struct sockaddr_in *sin, int *num);
int dht_uninit(DHT D);

/* This must be provided by the user. */
int dht_blacklisted(const struct sockaddr *sa, int salen);
void dht_hash(void *hash_return, int hash_size,
              void *v1, int len1,
              void *v2, int len2,
              void *v3, int len3);
int dht_random_bytes(void *buf, size_t size);

