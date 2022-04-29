#include<stdio.h>
#include<stdint.h>

typedef struct{
    char data[512];
} tar_block_t;

typedef struct {
    char name[100];
    uint64_t mode,
             uid,
             gid;
    char size[12],
         mtime[12];
    uint64_t chksum;
    char typeflag;
    char linkname[100];
    char magic[6];
    uint16_t version;
    char uname[32],
         gname[32];
    uint64_t devmajor,
             devminor;
    char prefix[155];
} __attribute__((packed)) tar_header_t;


struct posix_header
{                              /* byte offset */
  char name[100];               /*   0 */
  char mode[8];                 /* 100 */
  char uid[8];                  /* 108 */
  char gid[8];                  /* 116 */
  char size[12];                /* 124 */
  char mtime[12];               /* 136 */
  char chksum[8];               /* 148 */
  char typeflag;                /* 156 */
  char linkname[100];           /* 157 */
  char magic[6];                /* 257 */
  char version[2];              /* 263 */
  char uname[32];               /* 265 */
  char gname[32];               /* 297 */
  char devmajor[8];             /* 329 */
  char devminor[8];             /* 337 */
  char prefix[155];             /* 345 */
                                /* 500 */
};

typedef struct {
    tar_header_t header;
    char padding_[12];
} tar_header_block_t;


void print_offsets(){
    struct posix_header *h = NULL;
    printf("%ld -- %s\n", (size_t)(void*) &(h->name), "name");
    printf("%ld -- %s\n", (size_t)(void*) &(h->mode), "mode");
    printf("%ld -- %s\n", (size_t)(void*) &(h->uid), "uid");
    printf("%ld -- %s\n", (size_t)(void*) &(h->gid), "gid");
    printf("%ld -- %s\n", (size_t)(void*) &(h->size), "size");
    printf("%ld -- %s\n", (size_t)(void*) &(h->mtime), "mtime");
    printf("%ld -- %s\n", (size_t)(void*) &(h->chksum), "chksum");
    printf("%ld -- %s\n", (size_t)(void*) &(h->typeflag), "typeflag");
    printf("%ld -- %s\n", (size_t)(void*) &(h->linkname), "linkname");
    printf("%ld -- %s\n", (size_t)(void*) &(h->magic), "magic");
    printf("%ld -- %s\n", (size_t)(void*) &(h->version), "version");
    printf("%ld -- %s\n", (size_t)(void*) &(h->uname), "uname");
    printf("%ld -- %s\n", (size_t)(void*) &(h->gname), "gname");
    printf("%ld -- %s\n", (size_t)(void*) &(h->devmajor), "devmajor");
    printf("%ld -- %s\n", (size_t)(void*) &(h->devminor), "devminor");
    printf("%ld -- %s\n", (size_t)(void*) &(h->prefix), "prefix");
}

int main(void){
    printf("posix header size:%lu\n\n", sizeof(struct posix_header));
    printf("header size:%lu\n\n", sizeof(tar_header_t));
    printf("header size padded:%lu\n\n", sizeof(tar_header_block_t));
    printf("end size:%lu\n\n", sizeof(tar_block_t));
    print_offsets();
    return 0;
}