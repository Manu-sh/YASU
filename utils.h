typedef enum { ASCII, INT, OCT, HEX } DisplayAs;

/* return the byte readed (as size, not index), 0 if an error is occurred */
static inline int displayChunk(const char *buf, int size, DisplayAs as, FILE *stream) {

	unsigned char c = 0;
	int i = 0;

	switch (as) {
		case ASCII:
			while (i < size) fprintf(stream, "%c", (isgraph((c = buf[i++])) ? c : '.'));
			break;
		case INT:
			while (i < size) fprintf(stream, "%03d ", (c = buf[i++]));
			break;
		case OCT:
			while (i < size) fprintf(stream, "%03o ", (c = buf[i++]));
			break;
		case HEX:
			while (i < size) fprintf(stream, "%02x ", (c = buf[i++]));
			break;
	}

	return i;
}
