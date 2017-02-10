#ifndef _GTP_H_
#define _GTP_H_


#include <linux/types.h>

/* A simplified GTP-U header for TEID matching */

struct gtpheader {
	unsigned char flags;
	unsigned char type;
	__be16 len;
	__be32 teid;
}; 

#endif /* _GTP_H_ */
