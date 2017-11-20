/* sha1sum.c - print SHA-1 Message-Digest Algorithm
* Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
* Copyright (C) 2004 g10 Code GmbH
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the
* Free Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software Foundation,
* Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* SHA-1 coden take from gnupg 1.3.92.

Note, that this is a simple tool to be used for MS Windows.
*/
typedef unsigned int u32;
typedef struct {
	u32 h0, h1, h2, h3, h4;
	u32 nblocks;
	unsigned char buf[64];
	int count;
} SHA1_CONTEXT;

#ifdef  __cplusplus  
extern "C" {
#endif
	void sha1_init(SHA1_CONTEXT *hd);
	void sha1_write(SHA1_CONTEXT *hd, unsigned char *inbuf, size_t inlen);
	void sha1_final(SHA1_CONTEXT *hd);

#ifdef  __cplusplus  
}
#endif 