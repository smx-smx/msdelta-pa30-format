#include "getdeltainfo.h"
#include <stdio.h>  // TODO? fprintf
#include <string.h>   // memcmp, memcpy
#include "bitreader/bitreader.h"

static uint64_t read_uint64_LE(const unsigned char *buf)
{
  return (0
    | (((uint64_t)buf[0] <<  0) & 0x00000000000000FFLL)
    | (((uint64_t)buf[1] <<  8) & 0x000000000000FF00LL)
    | (((uint64_t)buf[2] << 16) & 0x0000000000FF0000LL)
    | (((uint64_t)buf[3] << 24) & 0x00000000FF000000LL)
    | (((uint64_t)buf[4] << 32) & 0x000000FF00000000LL)
    | (((uint64_t)buf[5] << 40) & 0x0000FF0000000000LL)
    | (((uint64_t)buf[6] << 48) & 0x00FF000000000000LL)
    | (((uint64_t)buf[7] << 56) & 0xFF00000000000000LL)
  );
}

int dpa_GetDeltaInfo(const dpa_span_t *input, dpa_header_info_t *ret, dpa_extra_info_t *ret_extra)
{
  if (!input || !ret) {
    return 0;
  }

  if (input->len < 12) {
    return 0;
  }

  unsigned n_read = 0;

  // detect and skip manifest magic
  if(memcmp(input->buf, "DCM\x01", 4) == 0){
    n_read += 4;
  }

  if (memcmp(input->buf + n_read, "PA30", 4) != 0) {
    if (memcmp(input->buf + n_read, "PA19", 4) == 0) {
      fprintf(stderr, "Not Implemented: fallback of PA19 files to legacy format\n");
    }
    fprintf(stderr, "Error: Expected PA30 signature\n"); // TODO? elsewhere / error code?
    return 0;
  }
  n_read += 4;
  ret->TargetFileTime = read_uint64_LE(input->buf + n_read);
  n_read += 8;

  dpa_bitreader_t br;
  if (!dpa_bitreader_init(&br, input->buf + n_read, input->len - n_read)) {
    return 0;
  }

  if (!dpa_bitreader_read_number64(&br, &ret->FileTypeSet) ||
      !dpa_bitreader_read_number64(&br, &ret->FileType) ||
      !dpa_bitreader_read_number64(&br, &ret->Flags) ||
      !dpa_bitreader_read_number(&br, &ret->TargetSize) ||
      !dpa_bitreader_read_number(&br, &ret->TargetHashAlgId)) {
    return 0;
  }

  dpa_span_t hash;
  if (!dpa_bitreader_read_buffer(&br, &hash)) {
    return 0;
  }

  if (hash.len > DPA_MAX_HASH_SIZE) {
    return 0;
  }
  ret->TargetHash.HashSize = hash.len;
  memcpy(ret->TargetHash.HashValue, hash.buf, hash.len);

  if (ret_extra) {
    if (!dpa_bitreader_read_buffer(&br, &ret_extra->preproc)) {
      return 0;
    }
    if (!dpa_bitreader_read_buffer(&br, &ret_extra->patch)) {
      return 0;
    }
    ret_extra->end = br.in.buf + br.pos - br.fill / 8;
  }

  return 1;
}

