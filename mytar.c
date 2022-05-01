#include<stdio.h>
#include<stdint.h>
#include<stdbool.h>
#include<string.h>
#include<stdlib.h>

#define debug(...) //(fprintf(stderr, "\tD>> " __VA_ARGS__), fputc('\n', stderr))
#define debug1(...) (fprintf(stderr, "\tD1>> " __VA_ARGS__), fputc('\n', stderr))
#define debug2(...) //(fprintf(stderr, "\tD2>> " __VA_ARGS__), fputc('\n', stderr))

#define LEN(arr) (sizeof(arr)/sizeof(*(arr)))
#define invoke0(func) ((func).function((func).context))
#define invoke(func, ...) ((func).function((func).context, ## __VA_ARGS__))

#define min(a,b) ((a) <= (b) ? (a) : (b))
#define max(a,b) ((a) >= (b) ? (a) : (b))

#define var __auto_type

#define count_to_nil(arr)({\
    size_t ret = 0;\
    for(var _count_to_nill_ptr___ = arr;*_count_to_nill_ptr___;++_count_to_nill_ptr___)++ret;\
    ret;\
})

#define swap(a,b)({\
    var _swap_left_ref__ = &(a);\
    var _swap_right_ref__ = &(b);\
    \
    var _swap_temp__ = *_swap_left_ref__;\
    *_swap_left_ref__ = *_swap_right_ref__;\
    *_swap_right_ref__ = _swap_temp__;\
    (void)0;\
})


#define Exit_Message(...) (fprintf(stderr, __VA_ARGS__), exit(1))
#define Warn_Message(...) (fprintf(stderr, __VA_ARGS__))

size_t fsize(FILE *f){
    size_t block_begin_pos = ftell(f);
    fseek(f, 0, SEEK_END);
    size_t ret = ftell(f);
    fseek(f, block_begin_pos, SEEK_SET);
    return ret;
}

#define MAX_BYTES_TO_STACKALLOC 1024




#define BLOCK_BYTES 512


typedef struct{
    char data[BLOCK_BYTES];
} tar_block_t;

static const tar_block_t ZERO_BLOCK;

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






size_t block_count_from_bytes(size_t bytes){
    return bytes/BLOCK_BYTES + !!(bytes%BLOCK_BYTES);
}

static bool is_end_block(const tar_block_t *block){

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

static int checksum(void *arr, size_t length){
    int ret = 0;
    for(unsigned char *p = (unsigned char*)arr; length > 0; ++p, --length)
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

static void printout_header_info(tar_header_t *header, FILE *output, bool is_verbose){
    (void)is_verbose;
    fprintf(output, "%s\n", header->name);
}



int iterate_archive(string_t fileName, string_t mode, tar_entry_action_t action){
    
    //DEFINITIONS:
    struct supplier_context{
        tar_block_t *buffer;
        size_t entry_bytes_remaining;
        FILE *file;
    };

    tar_block_t *iterate_archive_supplier(void *context_, size_t *block_size_bytes){
        struct supplier_context *ctx = (struct supplier_context *)context_;
        if(block_size_bytes) *block_size_bytes = 0;

        if(ctx->entry_bytes_remaining <= 0)
            return NULL;

        size_t to_read = min(BLOCK_BYTES, ctx->entry_bytes_remaining);
        size_t did_read = fread(&(ctx->buffer->data),1, to_read, ctx->file);
        if(did_read < to_read)
            Exit_Message("Something went terribly wrong with reading the file!\n");
        ctx->entry_bytes_remaining -= did_read;

        if(block_size_bytes) *block_size_bytes = did_read;

        return ctx->buffer;
    }

    //IMPLEMENTATION:
    union{
        tar_header_block_t header_block;
        tar_block_t block;
    } buffer;
    tar_block_t contents_buffer;


    FILE *f = fopen(fileName, mode);
    if(!f) Exit_Message("File %s not found", fileName);

    struct supplier_context supplier_context = {
        .buffer = &(contents_buffer),
        .file = f
    };
    
    tar_block_supplier_t block_supplier = {
        .function = iterate_archive_supplier, .context = &supplier_context
    };


    #define read_block() (fread(buffer.block.data, BLOCK_BYTES, 1, f) >= 1)

    while(!feof(f)){
        if(!read_block()){
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
        size_t block_begin_pos = ftell(f);

        size_t bytes_in_file = parse_octal_array(buffer.header_block.header.size, NULL);
        size_t num_of_blocks = block_count_from_bytes(bytes_in_file);


        supplier_context.entry_bytes_remaining = bytes_in_file;
        invoke(action, &(buffer.header_block), num_of_blocks, block_supplier);

        fseek(f, block_begin_pos + num_of_blocks*BLOCK_BYTES, SEEK_SET);
    }
    #undef read_block
    fclose(f);

    return 0;
}






int iterate_archive_with_whitelist_decorator(string_t fileName, string_t mode, tar_entry_action_t action, strings_list_t files_to_include){
    
    struct only_whitelist_files_decorator_context{
        tar_entry_action_t inner_action;
        strings_list_t files_to_include;
        bool *files_to_include_was_encountered_flags;
    };
    
    int only_whitelist_files_decorator(void *ctx_, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier){
        struct only_whitelist_files_decorator_context *ctx = (struct only_whitelist_files_decorator_context*)ctx_;
        
        bool *flag = ctx->files_to_include_was_encountered_flags;
        for(strings_list_t s = ctx->files_to_include; *s ; ++s, ++flag){
            if(strcmp(*s, begin->header.name)==0){
                if(*flag)
                    Warn_Message("File '%s' encountered for more then first time!", *s);
                *flag = true;
                return invoke(ctx->inner_action, begin, num_of_blocks, block_supplier);
            }
        }
        return 0;
    }


    size_t files_count;
    if(!files_to_include || !(files_count = count_to_nil(files_to_include)))
        return iterate_archive(fileName, mode, action);
    size_t flag_buffer_size = files_count;

    bool *flag_buffer = malloc(flag_buffer_size*sizeof(bool));
    if(!flag_buffer)
        Exit_Message("Out of memory!");

    for(size_t t = 0; t< flag_buffer_size ; ++t)   
        flag_buffer[t] = 0;
    
    struct only_whitelist_files_decorator_context ctx = {
        .inner_action = action,
        .files_to_include = files_to_include,
        .files_to_include_was_encountered_flags = flag_buffer
    };
    tar_entry_action_t decorated_action = {
        .function = only_whitelist_files_decorator,
        .context = &ctx
    };

    int ret = iterate_archive(fileName, mode, decorated_action);

    for(size_t t = 0; t< flag_buffer_size ; ++t){
        if(!flag_buffer[t]){
            Warn_Message("%s: Not found in archive\n", files_to_include[t]);
            if(!ret) ret = -1;
        }
    }

    free(flag_buffer);

    return ret;
}


    static int list_contents_action__lister(void *ctx, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier){
        (void)ctx;
        (void)num_of_blocks;
        (void)block_supplier;
        printf("%s ... %lu blocks\n", begin->header.name, num_of_blocks);

        return 0;
    }
//option -t
int list_contents_action(request_t *ctx){
    tar_entry_action_t perform_listing = {
        .function = list_contents_action__lister,
        .context = NULL
    };

    return iterate_archive_with_whitelist_decorator(ctx->file_name, "rb", perform_listing, ctx->files);
}



int extract_action(request_t *ctx){
    
    int impl(void *ctx, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier){
        (void)ctx;
        (void)num_of_blocks;

        int ret = 0;


        printout_header_info(&(begin->header), stdout, false);

        char *name = begin->header.name;
        FILE *output = fopen(name, "wb");
        if(!output){
            Warn_Message("Cannot open file %s for write!\n", name);
            ret = -1;
        }
        else{
            {size_t block_size = 0;
            for(tar_block_t *it; (it = invoke(block_supplier, &block_size)); ){
                if(fwrite(&(it->data), block_size, 1, output) != 1){
                    Warn_Message("Error writing the file %s\n", name);
                    ret = -1;
                    break;
                }
            }}
        }
        fclose(output);
        return ret;
    }


    tar_entry_action_t perform_extraction = {
        .function = impl,
        .context = NULL
    };

    return iterate_archive_with_whitelist_decorator(ctx->file_name, "rb", perform_extraction, ctx->files);
}






request_t parse_args(int argc, char **argv){
    request_t ret = {
        .action = NULL,
        .file_name = NULL,
        .isVerbose = false,
        .files = argv
    };


    int files_end_index = 0;
    for(int t = 1; t<argc ;++t){
        char *arg = argv[t];
        if(*arg == '-'){
            switch(arg[1]){
                case 'f':
                    if(arg[2]){
                        ret.file_name = arg + 2;
                    }else if((arg = argv[++t])){
                        ret.file_name = arg;
                    }else{
                        Exit_Message("Expected a filename but none provided!");
                    }
                    break;
                case 't':
                    ret.action = list_contents_action;
                    break;
                case 'x':
                    ret.action = extract_action;
                    break;
                case 'v':
                    ret.isVerbose = true;
                    break;
            }
        }else{
            ret.files[files_end_index++] = arg;
        }
    }

    ret.files[files_end_index++] = NULL;
    return ret;
}


int validate_request(const request_t *req){
    int error = 0;

    if(!req->file_name){
        error = -1;
        Warn_Message("No filename provided!\n");
    }
    if(!req->action){
        error = -1;
        Warn_Message("No action provided!\n");
    }
        

    if(error)
        Exit_Message("Exiting\n");
    return error;
}


int main(int argc, char **argv){
    (void)argc;
    (void)argv;

    request_t req = parse_args(argc, argv);
    validate_request(&req);

    req.action(&req);

    return 0;
}















void unused_funcs(void){
    (void)unused_funcs;
    (void)check_header_checksum;
}