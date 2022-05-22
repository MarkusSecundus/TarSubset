#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*---Exit codes-------------------------------------------------*/
#define CMD_OPTIONS_ERRNO 2
#define INVALID_FILE_ERRNO 2
#define UNSUPPORTED_HEADER_ERRNO 2
#define INVALID_ARCHIVE_ENTRY_ERRNO 2
#define OUT_OF_MEMORY_ERRNO 2

/*---Random utility functions-------------------------------------------------*/

#define LEN(arr) (sizeof(arr) / sizeof(*(arr)))
#define invoke(func, ...) ((func).function((func).context, ##__VA_ARGS__))

#define min(a, b) ((a) <= (b) ? (a) : (b))
#define max(a, b) ((a) >= (b) ? (a) : (b))

#define var __auto_type

static size_t fsize(FILE *f) {
  size_t block_begin_pos = ftell(f);
  fseek(f, 0, SEEK_END);
  size_t ret = ftell(f);
  fseek(f, block_begin_pos, SEEK_SET);
  return ret;
}

static void *malloc_checked(size_t size) {
  var ret = malloc(size);
  if (!ret)
    err(OUT_OF_MEMORY_ERRNO, "Out of memory!");
  return ret;
}

typedef char *string_t;
typedef string_t *strings_list_t;

#define Exit(errno, ...) errx(errno, __VA_ARGS__)
#define Warn(...) warnx(__VA_ARGS__)

/*---Tar block definition-------------------------------------------------*/

#define BLOCK_BYTES 512

typedef struct {
  char data[BLOCK_BYTES];
} tar_block_t;

static const tar_block_t ZERO_BLOCK;

typedef struct {      /* byte offset */
  char name[100];     /*   0 */
  char mode[8];       /* 100 */
  char uid[8];        /* 108 */
  char gid[8];        /* 116 */
  char size[12];      /* 124 */
  char mtime[12];     /* 136 */
  char chksum[8];     /* 148 */
  char typeflag;      /* 156 */
  char linkname[100]; /* 157 */
  char magic[6];      /* 257 */
  char version[2];    /* 263 */
  char uname[32];     /* 265 */
  char gname[32];     /* 297 */
  char devmajor[8];   /* 329 */
  char devminor[8];   /* 337 */
  char prefix[155];   /* 345 */
                      /* 500 */
} tar_header_t;

#define REGTYPE '0'         /* regular file */
#define AREGTYPE '\0'       /* regular file */
#define TMAGIC "ustar"      /* ustar and a null */
#define TOLDMAGIC "ustar  " /* ustar and a null */

typedef struct {
  tar_header_t header;
  char padding_[BLOCK_BYTES - sizeof(tar_header_t)];
} tar_header_block_t;

/*---Request object definition-------------------------------------------------*/

typedef struct request {
  string_t file_name;
  bool is_verbose;
  strings_list_t files;
  int (*action)(struct request *context);
} request_t;

/*---Functions for reporting specific error scenarios-------------------------------------------------*/

static void ERROR_This_does_not_look_like_a_tar_archive() {
  Warn("This does not look like a tar archive");
  Exit(INVALID_FILE_ERRNO, "Exiting with failure status due to previous errors");
}
static void ERROR_Unexpected_EOF_in_archive() {
  Warn("Unexpected EOF in archive");
  Exit(INVALID_ARCHIVE_ENTRY_ERRNO, "Error is not recoverable: exiting now");
}

/*---Utility functions for processing tar structures-------------------------------------------------*/

static size_t block_count_from_bytes(size_t bytes) {
  return bytes / BLOCK_BYTES + !!(bytes % BLOCK_BYTES);
}

static bool is_end_block(const tar_block_t *block) {

  return memcmp(block, &ZERO_BLOCK, BLOCK_BYTES) == 0;
}

static size_t count_until_null(void *arr) {
  size_t ret = 0;
  for (void **p = arr; *p; ++p)
    ++ret;
  return ret;
}

static unsigned int parse_octal(const char *c, size_t length, int *errno) {
  if (errno) *errno = 0;

  unsigned int ret = 0;

  for (; *c && length > 0; ++c, --length) {
    if (*c < '0' && *c > '8') {
      if (errno) *errno = 1;
      return -1;
    }
    ret *= 8;
    ret += *c - '0';
  }
  return ret;
}
#define parse_octal_array(field, errno) parse_octal((field), LEN(field), errno)

static unsigned int compute_checksum(void *arr, void *end_) {
  unsigned int ret = 0;
  for (unsigned char *p = arr, *end = end_; p < end; ++p)
    ret += *p;
  return ret;
}

static void validate_checksum(tar_header_t *header) {
  int errno = 0;
  var supposed_checksum = parse_octal_array(header->chksum, &errno);
  if (errno)
    Exit(INVALID_ARCHIVE_ENTRY_ERRNO, "Wrong checksum");

  var calculated_checksum = 256 // TODO: find out why adding 256 is needed!
                            + compute_checksum(header, &(header->chksum)) 
                            + compute_checksum(((void *)&(header->chksum)) + LEN(header->chksum), ((void *)header) + sizeof(tar_header_t));

  if (calculated_checksum != supposed_checksum)
    ERROR_This_does_not_look_like_a_tar_archive();
}

static void validate_header(tar_header_t *header) {
  if (header->typeflag != REGTYPE && header->typeflag != AREGTYPE)
    Exit(UNSUPPORTED_HEADER_ERRNO, "Unsupported header type: %d", header->typeflag);

  if (memcmp(header->magic, TMAGIC, LEN(header->magic)) && memcmp(header->magic, TOLDMAGIC, LEN(header->magic)))
    ERROR_This_does_not_look_like_a_tar_archive();

  validate_checksum(header);
}

void print_header_info(tar_header_block_t *block) {
  fprintf(stderr, "%s\n", block->header.name);
}

/*---Tar archive iteration -------------------------------------------------*/

/*      ---public definitions---*/
typedef struct {
  size_t (*function)(void *context, size_t bytes_available, char *buffer_to_write);
  void *context;
} tar_block_supplier_t;

typedef struct {
  int (*function)(void *context, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier);
  void *context;
} tar_entry_action_t;

/*      ---private helpers---*/

struct iterate_archive_supplier_context {
  size_t entry_bytes_remaining;
  FILE *file;
};

static size_t iterate_archive_supplier(void *context_, size_t bytes_available, char *buffer) {
  struct iterate_archive_supplier_context *ctx = (struct iterate_archive_supplier_context *)context_;

  if (ctx->entry_bytes_remaining <= 0)
    return 0;

  size_t to_read = min(bytes_available, ctx->entry_bytes_remaining);
  if (fread(buffer, 1, to_read, ctx->file) != to_read)
    ERROR_Unexpected_EOF_in_archive();
  ctx->entry_bytes_remaining -= to_read;

  return to_read;
}

/*      ---function implementation---*/
int iterate_archive(string_t file_name, string_t mode, tar_entry_action_t action) {

  union {
    tar_header_block_t header_block;
    tar_block_t block;
  } buffer;

  FILE *f = fopen(file_name, mode);
  if (!f)
    Exit(INVALID_FILE_ERRNO, "File %s not found", file_name);

  struct iterate_archive_supplier_context supplier_context = {
    .file = f
  };

  tar_block_supplier_t block_supplier = {
    .function = iterate_archive_supplier,
    .context = &supplier_context
  };

  const size_t file_size = fsize(f);

  int ret = 0;

#define read_block() (fread(buffer.block.data, BLOCK_BYTES, 1, f) >= 1)

  while (!feof(f)) {
    if (!read_block()) {
      break;
    }
    if (is_end_block(&(buffer.block))) {
      size_t zero_block_num = block_count_from_bytes(ftell(f));
      if (!read_block() || !is_end_block(&(buffer.block))) {
        Warn("A lone zero block at %lu", zero_block_num);
        break;
      }
      if (is_end_block(&(buffer.block)))
        break;
    }
    size_t block_begin_pos = ftell(f);

    size_t bytes_in_file =
        parse_octal_array(buffer.header_block.header.size, NULL);
    size_t num_of_blocks = block_count_from_bytes(bytes_in_file);

    validate_header(&(buffer.header_block.header));

    supplier_context.entry_bytes_remaining = bytes_in_file;
    ret |= invoke(action, &(buffer.header_block), num_of_blocks, block_supplier);

    if (bytes_in_file > (file_size - block_begin_pos))
      ERROR_Unexpected_EOF_in_archive();

    fseek(f, block_begin_pos + num_of_blocks * BLOCK_BYTES, SEEK_SET);
  }
#undef read_block
  fclose(f);

  return ret;
}

/*---Tar archive iteration with whitelist-------------------------------------------------*/

/*      ---private helpers---*/

struct iterate_archive_with_whitelist_action_decorator_context {
  tar_entry_action_t inner_action;
  strings_list_t files_to_include;
  bool *files_to_include_was_encountered_flags;
};
static int iterate_archive_with_whitelist_action_decorator(void *ctx_, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier) {
  struct iterate_archive_with_whitelist_action_decorator_context *ctx = (struct iterate_archive_with_whitelist_action_decorator_context *)ctx_;

  bool *flag = ctx->files_to_include_was_encountered_flags;
  for (strings_list_t s = ctx->files_to_include; *s; ++s, ++flag) {
    if (strcmp(*s, begin->header.name) == 0) {
      if (*flag)
        Warn("File '%s' encountered for more then first time!", *s);
      *flag = true;
      return invoke(ctx->inner_action, begin, num_of_blocks, block_supplier);
    }
  }
  return 0;
}

/*      ---function implementation---*/
int iterate_archive_with_whitelist(string_t file_name, string_t mode, tar_entry_action_t action, strings_list_t files_to_include) {

  size_t files_count;
  if (!files_to_include || !(files_count = count_until_null(files_to_include)))
    return iterate_archive(file_name, mode, action);
  size_t flag_buffer_size = files_count;

  bool *flag_buffer = malloc_checked(flag_buffer_size * sizeof(bool));

  for (size_t t = 0; t < flag_buffer_size; ++t)
    flag_buffer[t] = 0;

  struct iterate_archive_with_whitelist_action_decorator_context ctx = {
    .inner_action = action,
    .files_to_include = files_to_include,
    .files_to_include_was_encountered_flags = flag_buffer
  };
  tar_entry_action_t decorated_action = {
    .function = iterate_archive_with_whitelist_action_decorator,
    .context = &ctx
  };

  int ret = iterate_archive(file_name, mode, decorated_action);

  for (size_t t = 0; t < flag_buffer_size; ++t) {
    if (!flag_buffer[t]) {
      Warn("%s: Not found in archive", files_to_include[t]);
      if (!ret)
        ret = 2;
    }
  }

  free(flag_buffer);

  return ret;
}

static int list_contents_action__lister(void *ctx, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier) {
  (void)ctx;
  (void)num_of_blocks;
  (void)block_supplier;

  print_header_info(begin);
  return 0;
}
// option -t
int list_contents_action(request_t *ctx) {
  tar_entry_action_t perform_listing = {
    .function = list_contents_action__lister, 
    .context = NULL
  };

  return iterate_archive_with_whitelist(ctx->file_name, "rb", perform_listing, ctx->files);
}

struct extract_action_impl_context {
  bool is_verbose;
};

int extract_action_impl(void *ctx_, tar_header_block_t *begin, size_t num_of_blocks, tar_block_supplier_t block_supplier) {
  (void)num_of_blocks;

  char buffer[1024];

  struct extract_action_impl_context *ctx = (struct extract_action_impl_context *)ctx_;
  int ret = 0;

  if (ctx->is_verbose)
    print_header_info(begin);

  char *name = begin->header.name;
  FILE *output = fopen(name, "wb");
  if (!output) {
    Warn("Cannot open file %s for write!", name);
    ret = -1;
  } else {
    for (size_t block_size = 0;
         (block_size = invoke(block_supplier, LEN(buffer), buffer));) {
      if (fwrite(buffer, block_size, 1, output) != 1) {
        Warn("Error writing the file %s", name);
        ret = -1;
        break;
      }
    }
  }
  fclose(output);
  return ret;
}

int extract_action(request_t *ctx) {
  struct extract_action_impl_context action_ctx = {
    .is_verbose = ctx->is_verbose
  };

  tar_entry_action_t perform_extraction = {
    .function = extract_action_impl,
    .context = &action_ctx
  };

  return iterate_archive_with_whitelist(ctx->file_name, "rb", perform_extraction, ctx->files);
}

request_t parse_args(int argc, char **argv) {
  request_t ret = {
      .action = NULL,
      .file_name = NULL,
      .is_verbose = false, 
      .files = argv
  };

  int files_end_index = 0;
  for (int t = 1; t < argc; ++t) {
    char *arg = argv[t];
    if (*arg == '-') {
      switch (arg[1]) {
      case 'f':
        if (arg[2]) {
          ret.file_name = arg + 2;
        } else if ((arg = argv[++t])) {
          ret.file_name = arg;
        } else {
          Exit(CMD_OPTIONS_ERRNO, "Expected a filename but none provided!");
        }
        break;
      case 't':
        if (ret.action)
          Warn("Action specified multiple times - overriding the former request with '-t'");
        ret.action = list_contents_action;
        break;
      case 'x':
        if (ret.action)
          Warn("Action specified multiple times - overriding the former request with '-x'");
        ret.action = extract_action;
        break;
      case 'v':
        ret.is_verbose = true;
        break;
      default:
        Warn("Unknown option: -%c", arg[1]);
        break;
      }
    } else {
      ret.files[files_end_index++] = arg;
    }
  }

  ret.files[files_end_index++] = NULL;
  return ret;
}

int validate_request(const request_t *req) {
  int error = 0;

  if (!req->file_name) {
    error = CMD_OPTIONS_ERRNO;
    Warn("No filename provided!");
  }
  if (!req->action) {
    error = CMD_OPTIONS_ERRNO;
    Warn("No action provided!");
  }

  if (error)
    Exit(error, "Exiting with failure status due to previous errors");
  return error; //otherwise causes a warning
}

int main(int argc, char **argv) {
  request_t req = parse_args(argc, argv);
  validate_request(&req);

  var ret = req.action(&req);
  if (ret)
    Exit(ret, "Exiting with failure status due to previous errors");
  return ret;
}
