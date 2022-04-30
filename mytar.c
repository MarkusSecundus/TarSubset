#include<stdio.h>
#include<stdint.h>
#include<stdbool.h>
#include<string.h>
#include<stdlib.h>

#define debug(...) //(fprintf(stderr, "\tD>> " __VA_ARGS__), fputc('\n', stderr))
#define debug1(...) (fprintf(stderr, "\tD>> " __VA_ARGS__), fputc('\n', stderr))

#define LEN(arr) (sizeof(arr)/sizeof(*(arr)))
#define invoke0(func) ((func).function((func).context))
#define invoke(func, ...) ((func).function((func).context, ## __VA_ARGS__))

#define BLOCK_BYTES 512


#define Exit_Message(...) (fprintf(stderr, __VA_ARGS__), exit(1))
#define Warn_Message(...) (fprintf(stderr, __VA_ARGS__))

size_t block_count_from_bytes(size_t bytes){
    return bytes/BLOCK_BYTES + !!(bytes%BLOCK_BYTES);
}


size_t fsize(FILE *f){
    size_t current_pos = ftell(f);
    fseek(f, 0, SEEK_END);
    size_t ret = ftell(f);
    fseek(f, current_pos, SEEK_SET);
    return ret;
}


typedef struct{
    char data[BLOCK_BYTES];
} tar_block_t;

typedef struct 
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
} tar_header_t;

typedef struct {
    tar_header_t header;
    char padding_[BLOCK_BYTES - sizeof(tar_header_t)];
} tar_header_block_t;



typedef char* string_t;
typedef string_t *strings_list_t;



typedef struct request request_t;

typedef int (*user_action_t)(request_t *context);
struct request {
    string_t file_name;
    bool isVerbose;
    strings_list_t files;
    user_action_t action;
};








static bool is_end_block(const tar_block_t *block){
    static const tar_block_t ZERO_BLOCK;

    return memcmp(block, &ZERO_BLOCK, BLOCK_BYTES) == 0;
}



static int parse_octal(const char *c, size_t length, int *errno){
    if(errno) *errno = 0;

    int ret = 0;

    for(; *c && length > 0; ++c, --length){
        if(*c < '0' && *c > '8'){
            if(errno) *errno = 1;
            return -1;
        }
        ret *= 8;
        ret += *c - '0';
    }
    return ret;
}
#define parse_octal_array(field, errno) parse_octal((field), LEN(field), errno) 

static char checksum(void *arr, size_t length){
    char ret = 0;
    for(char *p = (char*)arr;length > 0; ++p, --length)
        ret += *p;
    return ret;
}


typedef struct{
    tar_block_t *(*function)(void *context, size_t *block_size_bytes);
    void *context;
} tar_block_supplier_t;
typedef struct{
    int (*function)(void *context, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier);
    void *context;
}tar_entry_action_t;


static int check_header_checksum(tar_header_t *header){
    int errno;
    int ret = checksum(header, sizeof(header)) != parse_octal_array(header->chksum, &errno);
    if(errno)
        return 2;
    return ret;
}




int iterate_archive(string_t fileName, string_t mode, strings_list_t names_to_include, tar_entry_action_t action){
    (void)names_to_include;

    debug("inside iterate_archive");

    union{
        tar_header_block_t header_block;
        tar_block_t block;
    } buffer;

    tar_block_supplier_t block_supplier = {
        .function = NULL, .context = NULL
    };

    debug("opening the file");
    FILE *f = fopen(fileName, mode);
    if(!f) Exit_Message("File %s not found", fileName);
    debug("file opened: %p", f);

    debug1("beginning stream position: %lu", ftell(f));
    size_t file_size = fsize(f);
    debug1("file size: %lubytes - %lf blocks", file_size, file_size*1.0/BLOCK_BYTES);

#define read_block() (fread(buffer.block.data, BLOCK_BYTES, 1, f) < 1)

    while(!feof(f)){
        debug1("current stream position: %lu", ftell(f));

        debug("starting fread");
        if(read_block()){
            debug1("fread returned non1");
            break;
        }
        if(is_end_block(&(buffer.block))){
            if(!read_block() ){
                Warn_Message("Only one of the two terminator zero-blocks present!");
                break;
            }
            if(is_end_block(&(buffer.block)))
                break;
        }

        debug("finished fread");
        size_t bytes_in_file = parse_octal_array(buffer.header_block.header.size, NULL);
        size_t num_of_blocks = block_count_from_bytes(bytes_in_file);
        debug1("bytes: %5lu -- %2lu (%s) blocks",bytes_in_file, num_of_blocks, buffer.header_block.header.size);
        
        debug("invoking the action");
        invoke(action, &(buffer.header_block), num_of_blocks, block_supplier);

        fseek(f, (num_of_blocks)*BLOCK_BYTES, SEEK_CUR);
    }
#undef read_block

    return 0;
}



    static int contents_lister(void *ctx, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier){
        (void)ctx;
        (void)num_of_blocks;
        (void)block_supplier;
        printf("%s ... %lu bytes\n", begin->header.name, num_of_blocks);
        return 0;
    }
//option -t
int list_contents_action(request_t *ctx){
    (void)ctx;
    tar_entry_action_t perform_listing = {
        .function = contents_lister,
        .context = NULL
    };

    debug("iterating archive");
    return iterate_archive(ctx->file_name, "rb", NULL, perform_listing);
    ;
}




int main(int argc, char **argv){
    (void)argc;
    (void)argv;

    request_t req = {
        .action = list_contents_action,
        .file_name = "./testfiles/arch.tar",
        .files = NULL,
        .isVerbose = false
    };

    list_contents_action(&req);

    return 0;
}















void unused_funcs(void){
    (void)unused_funcs;
    (void)contents_lister;
    (void)check_header_checksum;
    (void)is_end_block;
}