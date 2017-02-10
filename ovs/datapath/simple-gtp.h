#ifndef _SIMPLE_GTP_H_
#define _SIMPLE_GTP_H_


#include <linux/types.h>

/* A simplified GTP-U header for TEID matching */

struct simplegtphdr {
	unsigned char flags;
	unsigned char type;
	__be16 len;
	__be32 teid;
}; 

#endif /* _SIMPLE_GTP_H_ */
