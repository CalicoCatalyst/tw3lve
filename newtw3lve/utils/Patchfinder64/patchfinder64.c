//
//  patchfinder64.c
//  extra_recipe
//
//  Created by xerub on 06/06/2017.
//  Copyright © 2017 xerub. All rights reserved.
//

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "patchfinder64.h"

bool auth_ptrs = false;
typedef unsigned long long addr_t;
static addr_t kerndumpbase = -1;
static addr_t xnucore_base = 0;
static addr_t xnucore_size = 0;
static addr_t ppl_base = 0;
static addr_t ppl_size = 0;
static addr_t prelink_base = 0;
static addr_t prelink_size = 0;
static addr_t cstring_base = 0;
static addr_t cstring_size = 0;
static addr_t pstring_base = 0;
static addr_t pstring_size = 0;
static addr_t oslstring_base = 0;
static addr_t oslstring_size = 0;
static addr_t data_base = 0;
static addr_t data_size = 0;
static addr_t data_const_base = 0;
static addr_t data_const_size = 0;
static addr_t const_base = 0;
static addr_t const_size = 0;
static addr_t kernel_entry = 0;
static void *kernel_mh = 0;
static addr_t kernel_delta = 0;
bool monolithic_kernel = false;


#define IS64(image) (*(uint8_t *)(image) & 1)

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

/* generic stuff *************************************************************/

#define UCHAR_MAX 255

/* these operate on VA ******************************************************/

#define INSN_RET  0xD65F03C0, 0xFFFFFFFF
#define INSN_CALL 0x94000000, 0xFC000000
#define INSN_B    0x14000000, 0xFC000000
#define INSN_CBZ  0x34000000, 0xFC000000
#define INSN_ADRP 0x90000000, 0x9F000000

static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */
    
    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;
    
    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;
    
    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;
    
    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;
    
    /* ---- Do the matching ---- */
    
    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;
        
        /* otherwise, we need to skip some bytes and start again.
         Note that here we are getting the skip value based on the last byte
         of needle, no matter where we didn't match. So if needle is: "abcd"
         then we are skipping based on 'd' and that value will be 4, and
         for "abcdd" we again skip on 'd' but the value will be only 1.
         The alternative of pretending that the mismatched character was
         the last character is slower in the normal case (E.g. finding
         "abcd" in "...azcd..." gives 4 by using 'd' but only
         4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }
    
    return NULL;
}


/* patchfinder ***************************************************************/

static addr_t
step64(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += 4;
    }
    return 0;
}

static addr_t
step64_back(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start - length;
    while (start >= end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start -= 4;
    }
    return 0;
}


static addr_t
bof64(const uint8_t *buf, addr_t start, addr_t where)
{
    if (auth_ptrs) {
        for (; where >= start; where -= 4) {
            uint32_t op = *(uint32_t *)(buf + where);
            if (op == 0xD503237F) {
                return where;
            }
        }
        return 0;
    }
    for (; where >= start; where -= 4) {
        uint32_t op = *(uint32_t *)(buf + where);
        if ((op & 0xFFC003FF) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xFFF;
            //printf("0x%llx: ADD X29, SP, #0x%x\n", where + kerndumpbase, delta);
            if ((delta & 0xF) == 0) {
                addr_t prev = where - ((delta >> 4) + 1) * 4;
                uint32_t au = *(uint32_t *)(buf + prev);
                //printf("0x%llx: (%llx & %llx) == %llx\n", prev + kerndumpbase, au, 0x3BC003E0, au & 0x3BC003E0);
                if ((au & 0x3BC003E0) == 0x298003E0) {
                    //printf("%x: STP x, y, [SP,#-imm]!\n", prev);
                    return prev;
                } else if ((au & 0x7F8003FF) == 0x510003FF) {
                    //printf("%x: SUB SP, SP, #imm\n", prev);
                    return prev;
                }
                for (addr_t diff = 4; diff < delta/4+4; diff+=4) {
                    uint32_t ai = *(uint32_t *)(buf + where - diff);
                    // SUB SP, SP, #imm
                    //printf("0x%llx: (%llx & %llx) == %llx\n", where - diff + kerndumpbase, ai, 0x3BC003E0, ai & 0x3BC003E0);
                    if ((ai & 0x7F8003FF) == 0x510003FF) {
                        return where - diff;
                    }
                    // Not stp and not str
                    if (((ai & 0xFFC003E0) != 0xA90003E0) && (ai&0xFFC001F0) != 0xF90001E0) {
                        break;
                    }
                }
                // try something else
                while (where > start) {
                    where -= 4;
                    au = *(uint32_t *)(buf + where);
                    // SUB SP, SP, #imm
                    if ((au & 0xFFC003FF) == 0xD10003FF && ((au >> 10) & 0xFFF) == delta + 0x10) {
                        return where;
                    }
                    // STP x, y, [SP,#imm]
                    if ((au & 0xFFC003E0) != 0xA90003E0) {
                        where += 4;
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

static addr_t
xref64(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;
    uint64_t value[32];
    
    memset(value, 0, sizeof(value));
    
    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            continue;                // XXX should not XREF on its own?
            /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
             unsigned rd = op & 0x1F;
             unsigned rm = (op >> 16) & 0x1F;
             //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
             value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[reg] = value[rn] + imm;    // XXX address, not actual value
            /*} else if ((op & 0xF9C00000) == 0xF9000000) {
             unsigned rn = (op >> 5) & 0x1F;
             unsigned imm = ((op >> 10) & 0xFFF) << 3;
             //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
             if (!imm) continue;            // XXX not counted as true xref
             value[rn] = value[rn] + imm;    // XXX address, not actual value*/
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;        // XXX address, not actual value
        } else if ((op & 0xFC000000) == 0x94000000) {
            // BL addr
            signed imm = (op & 0x3FFFFFF) << 2;
            if (op & 0x2000000) {
                imm |= 0xf << 28;
            }
            unsigned adr = (unsigned)(i + imm);
            if (adr == what) {
                return i;
            }
        }
        // Don't match SP as an offset
        if (value[reg] == what && reg != 0x1f) {
            return i;
        }
    }
    return 0;
}

static addr_t
calc64(const uint8_t *buf, addr_t start, addr_t end, int which)
{
    addr_t i;
    uint64_t value[32];
    
    memset(value, 0, sizeof(value));
    
    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
             unsigned rd = op & 0x1F;
             unsigned rm = (op >> 16) & 0x1F;
             //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
             value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[reg] = value[rn] + imm;    // XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;            // XXX not counted as true xref
            value[rn] = value[rn] + imm;    // XXX address, not actual value
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;        // XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xb9400000) { // 32bit
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 2;
            if (!imm) continue;            // XXX not counted as true xref
            value[reg] = value[rn] + imm;    // XXX address, not actual value
        }
    }
    return value[which];
}


static addr_t
follow_call64(const uint8_t *buf, addr_t call)
{
    long long w;
    w = *(uint32_t *)(buf + call) & 0x3FFFFFF;
    w <<= 64 - 26;
    w >>= 64 - 26 - 2;
    return call + w;
}

static addr_t
follow_stub(const uint8_t *buf, addr_t call)
{
    addr_t stub = follow_call64(buf, call);
    if (!stub) return 0;
    
    if (monolithic_kernel) {
        return stub + kerndumpbase;
    }
    addr_t target_function_offset = calc64(buf, stub, stub+4*3, 16);
    if (!target_function_offset) return 0;
    
    return *(addr_t*)(buf + target_function_offset);
}

static addr_t
follow_cbz(const uint8_t *buf, addr_t cbz)
{
    return cbz + ((*(int *)(buf + cbz) & 0x3FFFFE0) << 10 >> 13);
}

/* kernel iOS10 **************************************************************/

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef NOT_DARWIN
#include <mach-o/loader.h>
#else
#include "mach-o_loader.h"
#endif

#ifdef VFS_H_included
#define INVALID_HANDLE NULL
static FHANDLE
OPEN(const char *filename, int oflag)
{
    // XXX use sub_reopen() to handle FAT
    return img4_reopen(file_open(filename, oflag), NULL, 0);
}
#define CLOSE(fd) (fd)->close(fd)
#define READ(fd, buf, sz) (fd)->read(fd, buf, sz)
static ssize_t
PREAD(FHANDLE fd, void *buf, size_t count, off_t offset)
{
    ssize_t rv;
    //off_t pos = fd->lseek(FHANDLE fd, 0, SEEK_CUR);
    fd->lseek(fd, offset, SEEK_SET);
    rv = fd->read(fd, buf, count);
    //fd->lseek(FHANDLE fd, pos, SEEK_SET);
    return rv;
}
#else
#define FHANDLE int
#define INVALID_HANDLE -1
#define OPEN open
#define CLOSE close
#define READ read
#define PREAD pread
#endif

static uint8_t *kernel = NULL;
static size_t kernel_size = 0;

int
init_kernel(size_t (*kread)(uint64_t, void *, size_t), addr_t kernel_base, const char *filename)
{
    size_t rv;
    uint8_t buf[0x4000];
    unsigned i, j;
    const struct mach_header *hdr = (struct mach_header *)buf;
    FHANDLE fd = INVALID_HANDLE;
    const uint8_t *q;
    addr_t min = -1;
    addr_t max = 0;
    int is64 = 0;
    
    if (filename == NULL) {
        if (!kread || !kernel_base) {
            return -1;
        }
        rv = kread(kernel_base, buf, sizeof(buf));
        if (rv != sizeof(buf) || !MACHO(buf)) {
            return -1;
        }
    } else {
        fd = OPEN(filename, O_RDONLY);
        if (fd == INVALID_HANDLE) {
            return -1;
        }
        rv = READ(fd, buf, sizeof(buf));
        if (rv != sizeof(buf) || !MACHO(buf)) {
            CLOSE(fd);
            return -1;
        }
    }
    
    if (IS64(buf)) {
        is64 = 4;
    }
    
    q = buf + sizeof(struct mach_header) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (min > seg->vmaddr && seg->vmsize > 0) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize && seg->vmsize > 0) {
                max = seg->vmaddr + seg->vmsize;
            }
            if (!strcmp(seg->segname, "__TEXT_EXEC")) {
                xnucore_base = seg->vmaddr;
                xnucore_size = seg->filesize;
            } else if (!strcmp(seg->segname, "__PPLTEXT")) {
                ppl_base = seg->vmaddr;
                ppl_size = seg->filesize;
            } else if (!strcmp(seg->segname, "__PLK_TEXT_EXEC")) {
                prelink_base = seg->vmaddr;
                prelink_size = seg->filesize;
            } else if (!strcmp(seg->segname, "__TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__cstring")) {
                        cstring_base = sec[j].addr;
                        cstring_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__os_log")) {
                        oslstring_base = sec[j].addr;
                        oslstring_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__const")) {
                        const_base = sec[j].addr;
                        const_size = sec[j].size;
                    }
                }
            } else if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__text")) {
                        pstring_base = sec[j].addr;
                        pstring_size = sec[j].size;
                    }
                }
            } else if (!strcmp(seg->segname, "__DATA_CONST")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__const")) {
                        data_const_base = sec[j].addr;
                        data_const_size = sec[j].size;
                    }
                }
            } else if (!strcmp(seg->segname, "__DATA")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__data")) {
                        data_base = sec[j].addr;
                        data_size = sec[j].size;
                    }
                }
            }
        } else if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
                uint64_t x[29];    /* General purpose registers x0-x28 */
                uint64_t fp;    /* Frame pointer x29 */
                uint64_t lr;    /* Link register x30 */
                uint64_t sp;    /* Stack pointer x31 */
                uint64_t pc;     /* Program counter */
                uint32_t cpsr;    /* Current program status register */
            } *thread = (void *)(ptr + 2);
            if (flavor == 6) {
                kernel_entry = thread->pc;
            }
        }
        q = q + cmd->cmdsize;
    }
    
    if (prelink_size == 0) {
        monolithic_kernel = true;
        prelink_base = xnucore_base;
        prelink_size = xnucore_size;
        pstring_base = cstring_base;
        pstring_size = cstring_size;
    }
    
    kerndumpbase = min;
    xnucore_base -= kerndumpbase;
    prelink_base -= kerndumpbase;
    cstring_base -= kerndumpbase;
    ppl_base -= kerndumpbase;
    pstring_base -= kerndumpbase;
    oslstring_base -= kerndumpbase;
    data_const_base -= kerndumpbase;
    data_base -= kerndumpbase;
    const_base -= kerndumpbase;
    kernel_size = max - min;
    
    if (filename == NULL) {
        kernel = malloc(kernel_size);
        if (!kernel) {
            return -1;
        }
        rv = kread(kerndumpbase, kernel, kernel_size);
        if (rv != kernel_size) {
            free(kernel);
            kernel = NULL;
            return -1;
        }
        
        kernel_mh = kernel + kernel_base - min;
    } else {
        kernel = calloc(1, kernel_size);
        if (!kernel) {
            CLOSE(fd);
            return -1;
        }
        
        q = buf + sizeof(struct mach_header) + is64;
        for (i = 0; i < hdr->ncmds; i++) {
            const struct load_command *cmd = (struct load_command *)q;
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (struct segment_command_64 *)q;
                size_t sz = PREAD(fd, kernel + seg->vmaddr - min, seg->filesize, seg->fileoff);
                if (sz != seg->filesize) {
                    CLOSE(fd);
                    free(kernel);
                    kernel = NULL;
                    return -1;
                }
                if (!kernel_mh) {
                    kernel_mh = kernel + seg->vmaddr - min;
                }
                if (!strcmp(seg->segname, "__PPLDATA")) {
                    auth_ptrs = true;
                } else if (!strcmp(seg->segname, "__LINKEDIT")) {
                    kernel_delta = seg->vmaddr - min - seg->fileoff;
                }
            }
            q = q + cmd->cmdsize;
        }
        
        CLOSE(fd);
    }
    return 0;
}

void
term_kernel(void)
{
    if (kernel != NULL) {
        free(kernel);
        kernel = NULL;
    }
}

addr_t
find_register_value(addr_t where, int reg)
{
    addr_t val;
    addr_t bof = 0;
    where -= kerndumpbase;
    if (where > xnucore_base) {
        bof = bof64(kernel, xnucore_base, where);
        if (!bof) {
            bof = xnucore_base;
        }
    } else if (where > prelink_base) {
        bof = bof64(kernel, prelink_base, where);
        if (!bof) {
            bof = prelink_base;
        }
    }
    val = calc64(kernel, bof, where, reg);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_reference(addr_t to, int n, enum text_bases text_base)
{
    addr_t ref, end;
    addr_t base = xnucore_base;
    addr_t size = xnucore_size;
    switch (text_base) {
        case text_xnucore_base:
            break;
        case text_prelink_base:
            if (prelink_base) {
                base = prelink_base;
                size = prelink_size;
            }
            break;
        case text_ppl_base:
            if (ppl_base != 0-kerndumpbase) {
                base = ppl_base;
                size = ppl_size;
            }
            break;
        default:
            printf("Unknown base %d\n", text_base);
            return 0;
            break;
    }
    if (n <= 0) {
        n = 1;
    }
    end = base + size;
    to -= kerndumpbase;
    do {
        ref = xref64(kernel, base, end, to);
        if (!ref) {
            return 0;
        }
        base = ref + 4;
    } while (--n > 0);
    return ref + kerndumpbase;
}

addr_t
find_strref(const char *string, int n, enum string_bases string_base, bool full_match, bool ppl_base)
{
    uint8_t *str;
    addr_t base;
    addr_t size;
    enum text_bases text_base = ppl_base?text_ppl_base:text_xnucore_base;
    
    switch (string_base) {
        case string_base_const:
            base = const_base;
            size = const_size;
            break;
        case string_base_data:
            base = data_base;
            size = data_size;
            break;
        case string_base_oslstring:
            base = oslstring_base;
            size = oslstring_size;
            break;
        case string_base_pstring:
            base = pstring_base;
            size = pstring_size;
            text_base = text_prelink_base;
            break;
        case string_base_cstring:
        default:
            base = cstring_base;
            size = cstring_size;
            break;
    }
    addr_t off = 0;
    while ((str = boyermoore_horspool_memmem(kernel + base + off, size - off, (uint8_t *)string, strlen(string)))) {
        // Only match the beginning of strings
        if ((str == kernel + base || *(str-1) == '\0') && (!full_match || strcmp((char *)str, string) == 0))
            break;
        off = str - (kernel + base) + 1;
    }
    if (!str) {
        return 0;
    }
    return find_reference(str - kernel + kerndumpbase, n, text_base);
}

addr_t
find_gPhysBase(void)
{
    addr_t ret, val;
    addr_t ref = find_strref("\"pmap_map_high_window_bd: insufficient pages", 1, string_base_cstring, false, false);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    ret = step64(kernel, ref, 64, INSN_RET);
    if (!ret) {
        // iOS 11
        ref = step64(kernel, ref, 1024, INSN_RET);
        if (!ref) {
            return 0;
        }
        ret = step64(kernel, ref + 4, 64, INSN_RET);
        if (!ret) {
            return 0;
        }
    }
    val = calc64(kernel, ref, ret, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_kernel_pmap(void)
{
    addr_t call, bof, val;
    addr_t ref = find_strref("\"pmap_map_bd\"", 1, string_base_cstring, false, false);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64_back(kernel, ref, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    bof = bof64(kernel, xnucore_base, call);
    if (!bof) {
        return 0;
    }
    val = calc64(kernel, bof, call, 2);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_amfiret(void)
{
    addr_t ret;
    addr_t ref = find_strref("AMFI: hook..execve() killing pid %u: %s\n", 1, string_base_pstring, false, false);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    ret = step64(kernel, ref, 512, INSN_RET);
    if (!ret) {
        return 0;
    }
    return ret + kerndumpbase;
}

addr_t
find_ret_0(void)
{
    addr_t off;
    uint32_t *k;
    k = (uint32_t *)(kernel + xnucore_base);
    for (off = 0; off < xnucore_size - 4; off += 4, k++) {
        if (k[0] == 0xAA1F03E0 && k[1] == 0xD65F03C0) {
            return off + xnucore_base + kerndumpbase;
        }
    }
    k = (uint32_t *)(kernel + prelink_base);
    for (off = 0; off < prelink_size - 4; off += 4, k++) {
        if (k[0] == 0xAA1F03E0 && k[1] == 0xD65F03C0) {
            return off + prelink_base + kerndumpbase;
        }
    }
    return 0;
}

addr_t
find_amfi_memcmpstub(void)
{
    addr_t call, dest, reg;
    addr_t ref = find_strref("%s: Possible race detected. Rejecting.", 1, string_base_pstring, false, false);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64_back(kernel, ref, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    dest = follow_call64(kernel, call);
    if (!dest) {
        return 0;
    }
    reg = calc64(kernel, dest, dest + 8, 16);
    if (!reg) {
        return 0;
    }
    return reg + kerndumpbase;
}

addr_t
find_sbops(void)
{
    addr_t off, what;
    uint8_t *str = boyermoore_horspool_memmem(kernel + pstring_base, pstring_size, (uint8_t *)"Seatbelt sandbox policy", sizeof("Seatbelt sandbox policy") - 1);
    if (!str) {
        return 0;
    }
    what = str - kernel + kerndumpbase;
    for (off = 0; off < kernel_size - prelink_base; off += 8) {
        if (*(uint64_t *)(kernel + prelink_base + off) == what) {
            return *(uint64_t *)(kernel + prelink_base + off + 24);
        }
    }
    return 0;
}

addr_t
find_lwvm_mapio_patch(void)
{
    addr_t call, dest, reg;
    addr_t ref = find_strref("_mapForIO", 1, string_base_pstring, false, false);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64(kernel, ref, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64(kernel, call + 4, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    dest = follow_call64(kernel, call);
    if (!dest) {
        return 0;
    }
    reg = calc64(kernel, dest, dest + 8, 16);
    if (!reg) {
        return 0;
    }
    return reg + kerndumpbase;
}

addr_t
find_lwvm_mapio_newj(void)
{
    addr_t call;
    addr_t ref = find_strref("_mapForIO", 1, string_base_pstring, false, false);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64(kernel, ref, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64(kernel, call + 4, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64(kernel, call + 4, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64_back(kernel, call, 64, INSN_B);
    if (!call) {
        return 0;
    }
    return call + 4 + kerndumpbase;
}

addr_t
find_cpacr_write(void)
{
    addr_t off;
    uint32_t *k;
    k = (uint32_t *)(kernel + xnucore_base);
    for (off = 0; off < xnucore_size - 4; off += 4, k++) {
        if (k[0] == 0xd5181040) {
            return off + xnucore_base + kerndumpbase;
        }
    }
    return 0;
}

addr_t
find_str(const char *string)
{
    uint8_t *str = boyermoore_horspool_memmem(kernel, kernel_size, (uint8_t *)string, strlen(string));
    if (!str) {
        return 0;
    }
    return str - kernel + kerndumpbase;
}

addr_t
find_entry(void)
{
    /* XXX returns an unslid address */
    return kernel_entry;
}

const unsigned char *
find_mh(void)
{
    return kernel_mh;
}

addr_t
find_amfiops(void)
{
    addr_t off, what;
    uint8_t *str = boyermoore_horspool_memmem(kernel + pstring_base, pstring_size, (uint8_t *)"Apple Mobile File Integrity", sizeof("Apple Mobile File Integrity") - 1);
    if (!str) {
        return 0;
    }
    what = str - kernel + kerndumpbase;
    /* XXX will only work on a dumped kernel */
    for (off = 0; off < kernel_size - prelink_base; off += 8) {
        if (*(uint64_t *)(kernel + prelink_base + off) == what) {
            return *(uint64_t *)(kernel + prelink_base + off + 0x18);
        }
    }
    return 0;
}

addr_t
find_sysbootnonce(void)
{
    addr_t off, what;
    uint8_t *str = boyermoore_horspool_memmem(kernel + cstring_base, cstring_size, (uint8_t *)"com.apple.System.boot-nonce", sizeof("com.apple.System.boot-nonce") - 1);
    if (!str) {
        return 0;
    }
    what = str - kernel + kerndumpbase;
    for (off = 0; off < kernel_size - xnucore_base; off += 8) {
        if (*(uint64_t *)(kernel + xnucore_base + off) == what) {
            return xnucore_base + off + 8 + 4 + kerndumpbase;
        }
    }
    return 0;
}

addr_t
find_trustcache(void)
{
    if (auth_ptrs) {
        addr_t ref = find_strref("\"loadable trust cache buffer too small (%ld) for entries claimed (%d)\"", 1, string_base_cstring, false, true);
        if (!ref) return 0;
        
        ref -= kerndumpbase;
        
        addr_t val = calc64(kernel, ref-32*4, ref-24*4, 8);
        if (!val) return 0;
        
        return val + kerndumpbase;
    }
    
    addr_t call, func, val, adrp;
    int reg;
    uint32_t op;
    
    addr_t ref = find_strref("%s: only allowed process can check the trust cache", 1, string_base_pstring, false, false); // Trying to find AppleMobileFileIntegrityUserClient::isCdhashInTrustCache
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64_back(kernel, ref, 11 * 4, INSN_CALL);
    if (!call) {
        return 0;
    }
    func = follow_call64(kernel, call);
    if (!func) {
        return 0;
    }
    call = step64(kernel, func, 8 * 4, INSN_CALL);
    if (!call) {
        return 0;
    }
    func = follow_call64(kernel, call);
    if (!func) {
        return 0;
    }
    call = step64(kernel, func, 8 * 4, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64(kernel, call + 4, 8 * 4, INSN_CALL);
    if (!call) {
        return 0;
    }
    func = follow_call64(kernel, call);
    if (!func) {
        return 0;
    }
    
    call = step64(kernel, func, 12 * 4, INSN_CALL);
    if (!call) {
        return 0;
    }
    
    val = calc64(kernel, call, call + 6 * 4, 21);
    if (!val) {
        func = follow_stub(kernel, call);
        if (!func) return 0;
        func -=  kerndumpbase;
        addr_t movw = step64(kernel, func, 0x300, 0x52800280, 0xffffffe0);
        if (!movw) return 0;
        adrp = step64_back(kernel, movw, 0x10, INSN_ADRP);
        if (!adrp) return 0;
        op = *(uint32_t*)(kernel + adrp + 4);
        reg = op&0x1F;
        val = calc64(kernel, adrp, movw, reg);
        if (!val) return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_amficache(void)
{
    addr_t cbz, call, func, val;
    addr_t ref = find_strref("amfi_prevent_old_entitled_platform_binaries", 1, string_base_pstring, false, false);
    if (!ref) {
        // iOS 11
        ref = find_strref("com.apple.MobileFileIntegrity", 1, string_base_pstring, false, false);
        if (!ref) {
            return 0;
        }
        ref -= kerndumpbase;
        call = step64(kernel, ref, 64, INSN_CALL);
        if (!call) {
            return 0;
        }
        call = step64(kernel, call + 4, 64, INSN_CALL);
        goto okay;
    }
    ref -= kerndumpbase;
    cbz = step64(kernel, ref, 32, INSN_CBZ);
    if (!cbz) {
        return 0;
    }
    call = step64(kernel, follow_cbz(kernel, cbz), 4, INSN_CALL);
okay:
    if (!call) {
        return 0;
    }
    func = follow_call64(kernel, call);
    if (!func) {
        return 0;
    }
    val = calc64(kernel, func, func + 16, 8);
    if (!val) {
        ref = find_strref("%s: only allowed process can check the trust cache", 1, string_base_pstring, false, false); // Trying to find AppleMobileFileIntegrityUserClient::isCdhashInTrustCache
        if (!ref) {
            return 0;
        }
        ref -= kerndumpbase;
        call = step64_back(kernel, ref, 11 * 4, INSN_CALL);
        if (!call) {
            return 0;
        }
        func = follow_call64(kernel, call);
        if (!func) {
            return 0;
        }
        call = step64(kernel, func, 8 * 4, INSN_CALL);
        if (!call) {
            return 0;
        }
        func = follow_call64(kernel, call);
        if (!func) {
            return 0;
        }
        call = step64(kernel, func, 8 * 4, INSN_CALL);
        if (!call) {
            return 0;
        }
        call = step64(kernel, call + 4, 8 * 4, INSN_CALL);
        if (!call) {
            return 0;
        }
        func = follow_call64(kernel, call);
        if (!func) {
            return 0;
        }
        call = step64(kernel, func, 12 * 4, INSN_CALL);
        if (!call) {
            return 0;
        }
        
        val = calc64(kernel, call, call + 6 * 4, 21);
    }
    return val + kerndumpbase;
}

/* extra_recipe **************************************************************/

#define INSN_STR8 0xF9000000 | 8, 0xFFC00000 | 0x1F
#define INSN_POPS 0xA9407BFD, 0xFFC07FFF

addr_t
find_AGXCommandQueue_vtable(void)
{
    addr_t val, str8;
    addr_t ref = find_strref("AGXCommandQueue", 1, string_base_pstring, false, false);
    if (!ref) {
        return 0;
    }
    val = find_register_value(ref, 0);
    if (!val) {
        return 0;
    }
    ref = find_reference(val, 1, 1);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    str8 = step64(kernel, ref, 32, INSN_STR8);
    if (!str8) {
        return 0;
    }
    val = calc64(kernel, ref, str8, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_allproc(void)
{
    addr_t val, bof, str8;
    addr_t ref = find_strref("\"pgrp_add : pgrp is dead adding process\"", 1, string_base_cstring, false, false);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    bof = bof64(kernel, xnucore_base, ref);
    if (!bof) {
        return 0;
    }
    str8 = step64_back(kernel, ref, ref - bof, INSN_STR8);
    if (!str8) {
        // iOS 11
        addr_t ldp = step64(kernel, ref, 1024, INSN_POPS);
        if (!ldp) {
            return 0;
        }
        str8 = step64_back(kernel, ldp, ldp - bof, INSN_STR8);
        if (!str8) {
            return 0;
        }
    }
    val = calc64(kernel, bof, str8, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_call5(void)
{
    addr_t bof;
    uint8_t gadget[] = { 0x95, 0x5A, 0x40, 0xF9, 0x68, 0x02, 0x40, 0xF9, 0x88, 0x5A, 0x00, 0xF9, 0x60, 0xA2, 0x40, 0xA9 };
    uint8_t *str = boyermoore_horspool_memmem(kernel + prelink_base, prelink_size, gadget, sizeof(gadget));
    if (!str) {
        return 0;
    }
    bof = bof64(kernel, prelink_base, str - kernel);
    if (!bof) {
        return 0;
    }
    return bof + kerndumpbase;
}

addr_t
find_realhost(addr_t priv)
{
    addr_t val;
    if (!priv) {
        return 0;
    }
    priv -= kerndumpbase;
    val = calc64(kernel, priv, priv + 12, 0);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

/*
 *
 * @ninjaprawn's patches
 *
 */

addr_t find_vfs_context_current(void) {
    addr_t str = find_strref("/private/var/tmp/wav%u_%uchans.wav", 1, string_base_pstring, false, false);
    if (!str) return 0;
    str -= kerndumpbase;
    
    addr_t func = bof64(kernel, prelink_base, str);
    if (!func) return 0;
    
    addr_t call = step64(kernel, func, 0x100, INSN_CALL);
    if (!call) return 0;
    
    return follow_stub(kernel, call);
}

addr_t find_vnode_lookup(void) {
    addr_t hfs_str = find_strref("hfs: journal open cb: error %d looking up device %s (dev uuid %s)\n", 1, string_base_pstring, false, false);
    if (!hfs_str) return 0;
    
    hfs_str -= kerndumpbase;
    
    addr_t call_to_stub = step64_back(kernel, hfs_str, 10*4, INSN_CALL);
    if (!call_to_stub) return 0;
    
    return follow_stub(kernel, call_to_stub);
}

addr_t find_vnode_put(void) {
    addr_t err_str = find_strref("getparent(%p) != parent_vp(%p)", 1, string_base_oslstring, false, false);
    if (!err_str)
        err_str = find_strref("KBY: getparent(%p) != parent_vp(%p)", 1, string_base_pstring, false, false);
    if (!err_str)
        err_str = find_strref("getparent(%p) != parent_vp(%p)", 1, string_base_pstring, false, false);
    
    if (!err_str) return 0;
    
    err_str -= kerndumpbase;
    
    addr_t call_to_os_log = step64(kernel, err_str, 20*4, INSN_CALL);
    if (!call_to_os_log) return 0;
    
    addr_t call_to_vn_getpath = step64(kernel, call_to_os_log + 4, 20*4, INSN_CALL);
    if (!call_to_vn_getpath) return 0;
    
    addr_t call_to_stub = step64(kernel, call_to_vn_getpath + 4, 20*4, INSN_CALL);
    if (!call_to_stub) return 0;
    
    return follow_stub(kernel, call_to_stub);
}

addr_t find_vnode_getfromfd(void) {
    
    addr_t ent_str = find_strref("rootless_storage_class_entitlement", 1, string_base_pstring, false, false);
    
    if (!ent_str) {
        return 0;
    }
    
    ent_str -= kerndumpbase;
    
    addr_t call_to_unk1 = step64(kernel, ent_str, 20*4, INSN_CALL);
    
    if (!call_to_unk1) {
        return 0;
    }
    
    addr_t call_to_strlcpy = step64(kernel, call_to_unk1 + 4, 20*4, INSN_CALL);
    
    if (!call_to_strlcpy) {
        return 0;
    }
    
    addr_t call_to_strlcat = step64(kernel, call_to_strlcpy + 4, 20*4, INSN_CALL);
    
    if (!call_to_strlcat) {
        return 0;
    }
    
    addr_t call_to_unk2 = step64(kernel, call_to_strlcat + 4, 20*4, INSN_CALL);
    
    if (!call_to_unk2) {
        return 0;
    }
    
    addr_t call_to_unk3 = step64(kernel, call_to_unk2 + 4, 20*4, INSN_CALL);
    
    if (!call_to_unk3) {
        return 0;
    }
    
    addr_t call_to_vfs_context_create = step64(kernel, call_to_unk3 + 4, 20*4, INSN_CALL);
    
    if (!call_to_vfs_context_create) {
        return 0;
    }
    
    addr_t call_to_stub = step64(kernel, call_to_vfs_context_create + 4, 20*4, INSN_CALL);
    if (!call_to_stub) return 0;
    
    return follow_stub(kernel, call_to_stub);
}

addr_t find_vnode_getattr(void) {
    addr_t error_str = find_strref("\"add_fsevent: you can't pass me a NULL vnode ptr (type %d)!\\n\"", 1, string_base_cstring, false, false);
    
    if (!error_str) {
        return 0;
    }
    
    error_str -= kerndumpbase;
    error_str += 12; // Jump over the panic call
    
    addr_t call_to_target = step64(kernel, error_str, 30*4, INSN_CALL);
    
    if (!call_to_target) {
        return 0;
    }
    
    addr_t offset_to_target = follow_call64(kernel, call_to_target);
    
    if (!offset_to_target) {
        return 0;
    }
    
    return offset_to_target + kerndumpbase;
}

addr_t find_SHA1Init(void) {
    addr_t id_str = find_strref("CrashReporter-ID", 1, string_base_pstring, false, false);
    
    if (!id_str) {
        return 0;
    }
    
    id_str -= kerndumpbase;
    
    addr_t call_to_hash_function = step64(kernel, id_str, 10*4, INSN_CALL);
    
    if (!call_to_hash_function) {
        return 0;
    }
    
    addr_t hash_function = follow_call64(kernel, call_to_hash_function);
    
    if (!hash_function) {
        return 0;
    }
    
    addr_t call_to_stub = step64(kernel, hash_function, 20*4, INSN_CALL);
    if (!call_to_stub) return 0;
    
    return follow_stub(kernel, call_to_stub);
}

addr_t find_SHA1Update(void) {
    addr_t id_str = find_strref("CrashReporter-ID", 1, string_base_pstring, false, false);
    if (!id_str) {
        return 0;
    }
    
    id_str -= kerndumpbase;
    
    addr_t call_to_hash_function = step64(kernel, id_str, 10*4, INSN_CALL);
    
    if (!call_to_hash_function) {
        return 0;
    }
    
    addr_t hash_function = follow_call64(kernel, call_to_hash_function);
    
    if (!hash_function) {
        return 0;
    }
    
    addr_t call_to_sha1init = step64(kernel, hash_function, 20*4, INSN_CALL);
    
    if (!call_to_sha1init) {
        return 0;
    }
    
    addr_t call_to_stub = step64(kernel, call_to_sha1init + 4, 20*4, INSN_CALL);
    if (!call_to_stub) return 0;
    
    return follow_stub(kernel, call_to_stub);
}


addr_t find_SHA1Final(void) {
    addr_t id_str = find_strref("CrashReporter-ID", 1, string_base_pstring, false, false);
    
    if (!id_str) {
        return 0;
    }
    
    id_str -= kerndumpbase;
    
    addr_t call_to_hash_function = step64(kernel, id_str, 10*4, INSN_CALL);
    
    if (!call_to_hash_function) {
        return 0;
    }
    
    addr_t hash_function = follow_call64(kernel, call_to_hash_function);
    
    if (!hash_function) {
        return 0;
    }
    
    addr_t call_to_sha1init = step64(kernel, hash_function, 20*4, INSN_CALL);
    
    if (!call_to_sha1init) {
        return 0;
    }
    
    addr_t call_to_sha1update = step64(kernel, call_to_sha1init + 4, 20*4, INSN_CALL);
    
    if (!call_to_sha1update) {
        return 0;
    }
    
    addr_t call_to_stub = step64(kernel, call_to_sha1update + 4, 20*4, INSN_CALL);
    if (!call_to_stub) return 0;
    
    return follow_stub(kernel, call_to_stub);
}

addr_t find_csblob_entitlements_dictionary_set(void) {
    addr_t ent_str = find_strref("entitlements are not a dictionary", 1, string_base_pstring, false, false);
    
    if (!ent_str) {
        return 0;
    }
    
    ent_str -= kerndumpbase;
    
    addr_t call_to_lck_mtx_lock = step64(kernel, ent_str, 20*4, INSN_CALL);
    
    if (!call_to_lck_mtx_lock) {
        return 0;
    }
    
    addr_t call_to_csblob_entitlements_dictionary_copy = step64(kernel, call_to_lck_mtx_lock + 4, 20*4, INSN_CALL);
    
    if (!call_to_csblob_entitlements_dictionary_copy) {
        return 0;
    }
    
    addr_t call_to_stub = step64(kernel, call_to_csblob_entitlements_dictionary_copy + 4, 20*4, INSN_CALL);
    if (!call_to_stub) return 0;
    
    return follow_stub(kernel, call_to_stub);
}

addr_t find_kernel_task(void) {
    if (monolithic_kernel) {
        addr_t str = find_strref("\"shouldn't be applying exception notification", 2, string_base_cstring, false, false);
        if (!str) return 0;
        str -= kerndumpbase;
        
        addr_t call = step64_back(kernel, str, 0x10, INSN_CALL);
        if (!call) return 0;
        
        addr_t task_suspend = follow_call64(kernel, call);
        if (!task_suspend) return 0;
        
        addr_t adrp = step64(kernel, task_suspend, 20*4, INSN_ADRP);
        if (!adrp) return 0;
        
        addr_t kern_task = calc64(kernel, adrp, adrp + 0x8, 8);
        if (!kern_task) return 0;
        
        return kern_task + kerndumpbase;
    }
    
    addr_t term_str = find_strref("\"thread_terminate\"", 1, string_base_cstring, false, false);
    
    if (!term_str) {
        return 0;
    }
    
    term_str -= kerndumpbase;
    
    addr_t thread_terminate = bof64(kernel, xnucore_base, term_str);
    
    if (!thread_terminate) {
        return 0;
    }
    
    addr_t call_to_unk1 = step64(kernel, thread_terminate, 20*4, INSN_CALL);
    
    if (!call_to_unk1) {
        return 0;
    }
    
    addr_t kern_task = calc64(kernel, thread_terminate, call_to_unk1, 9);
    
    if (!kern_task) {
        return 0;
    }
    
    return kern_task + kerndumpbase;
}


addr_t find_kernproc(void) {
    addr_t ret_str = find_strref("\"returning child proc which is not cur_act\"", 1, string_base_cstring, false, false);
    
    if (!ret_str) {
        return 0;
    }
    
    ret_str -= kerndumpbase;
    
    addr_t end;
    int reg = 0;
    if (monolithic_kernel) {
        addr_t adrp = step64(kernel, ret_str, 20*4, INSN_ADRP);
        if (!adrp) return 0;
        uint32_t op = *(uint32_t*)(kernel + adrp + 4);
        reg = op & 0x1f;
        
        end = step64(kernel, adrp, 20*4, INSN_CALL);
        if (!end) return 0;
    } else {
        reg = 19;
        end = step64(kernel, ret_str, 20*4, INSN_RET);
        
        if (!end) {
            return 0;
        }
    }
    
    addr_t kernproc = calc64(kernel, ret_str, end, reg);
    
    if (!kernproc) {
        return 0;
    }
    
    return kernproc + kerndumpbase;
}

addr_t find_vnode_recycle(void) {
    addr_t error_str = find_strref("\"vnode_put(%p): iocount < 1\"", 1, string_base_cstring, false, false);
    
    if (!error_str) {
        return 0;
    }
    
    error_str -= kerndumpbase;
    
    if (monolithic_kernel) {
        addr_t tbnz = step64(kernel, error_str, 0x400, 0x37100000, 0xFFF80000);
        if (!tbnz) return 0;
        
        addr_t call_to_target = step64(kernel, tbnz + 4, 40*4, INSN_CALL);
        if (!call_to_target) return 0;
        
        addr_t func = follow_call64(kernel, call_to_target);
        if (!func) return 0;
        return func + kerndumpbase;
    }
    
    addr_t call_to_lck_mtx_unlock = step64(kernel, error_str + 4, 40*4, INSN_CALL);
    
    if (!call_to_lck_mtx_unlock) {
        return 0;
    }
    
    addr_t call_to_unknown1 = step64(kernel, call_to_lck_mtx_unlock + 4, 40*4, INSN_CALL);
    
    if (!call_to_unknown1) {
        return 0;
    }
    
    addr_t offset_to_unknown1 = follow_call64(kernel, call_to_unknown1);
    
    if (!offset_to_unknown1) {
        return 0;
    }
    
    addr_t call_to_target = step64(kernel, offset_to_unknown1 + 4, 40*4, INSN_CALL);
    
    if (!call_to_target) {
        return 0;
    }
    
    addr_t offset_to_target = follow_call64(kernel, call_to_target);
    
    if (!offset_to_target) {
        return 0;
    }
    
    return offset_to_target + kerndumpbase;
}

addr_t find_lck_mtx_lock(void) {
    addr_t strref = find_strref("nxprov_detacher", 1, string_base_cstring, false, false);
    if (!strref) return 0;
    
    strref -= kerndumpbase;
    
    addr_t call_to_target = step64_back(kernel, strref - 4, 0x10, INSN_CALL);
    if (!call_to_target) return 0;
    
    addr_t offset_to_target = follow_call64(kernel, call_to_target);
    if (!offset_to_target) return 0;
    
    // Did we really find lck_mtx_lock_contended?
    call_to_target = step64_back(kernel, offset_to_target, 0x4, INSN_B);
    if (call_to_target) {
        addr_t target = follow_call64(kernel, call_to_target);
        if (target == offset_to_target) {
            // Nope
            offset_to_target = bof64(kernel, xnucore_base, call_to_target);
            if (!offset_to_target) return 0;
        }
    }
    
    
    return offset_to_target + kerndumpbase;
}

addr_t find_lck_mtx_unlock(void) {
    addr_t strref = find_strref("nxprov_detacher", 1, string_base_cstring, false, false);
    if (!strref) return 0;
    
    strref -= kerndumpbase;
    
    addr_t call = step64(kernel, strref + 4, 0x100, INSN_CALL);
    if (!call) return 0;
    
    addr_t call_to_target = step64(kernel, call + 4, 0x10, INSN_CALL);
    if (!call_to_target) return 0;
    
    addr_t offset_to_target = follow_call64(kernel, call_to_target);
    if (!offset_to_target) return 0;
    
    return offset_to_target + kerndumpbase;
}

addr_t find_strlen(void) {
    addr_t xnu_str = find_strref("AP-xnu", 1, string_base_cstring, false, false);
    
    if (!xnu_str) {
        return 0;
    }
    
    xnu_str -= kerndumpbase;
    
    addr_t call_to_target = step64(kernel, xnu_str, 40*4, INSN_CALL);
    
    if (!call_to_target) {
        return 0;
    }
    
    addr_t offset_to_target = follow_call64(kernel, call_to_target);
    
    if (!offset_to_target) {
        return 0;
    }
    
    return offset_to_target + kerndumpbase;
}

addr_t find_add_x0_x0_0x40_ret(void)
{
    addr_t off;
    uint32_t* k;
    k = (uint32_t*)(kernel + xnucore_base);
    for (off = 0; off < xnucore_size - 4; off += 4, k++) {
        if (k[0] == 0x91010000 && k[1] == 0xD65F03C0) {
            return off + xnucore_base + kerndumpbase;
        }
    }
    k = (uint32_t*)(kernel + prelink_base);
    for (off = 0; off < prelink_size - 4; off += 4, k++) {
        if (k[0] == 0x91010000 && k[1] == 0xD65F03C0) {
            return off + prelink_base + kerndumpbase;
        }
    }
    return 0;
}

/*
 *
 *
 *
 */

/*
 *
 * @Cryptiiiic's patches
 *
 */

addr_t find_boottime(void) {
    addr_t ref = find_strref("%s WARNING: PMU offset is less then sys PMU", 1, string_base_oslstring, false, false);
    
    if (!ref) {
        ref = find_strref("%s WARNING: UTC time is less then sys time, (%lu s %d u) UTC (%lu s %d u) sys\n", 1, string_base_oslstring, false, false);
        if (!ref) {
            return 0;
        }
    }
    
    ref -= kerndumpbase;
    
    // ADRP Xm, #_boottime@PAGE
    ref = step64(kernel, ref, 0x4D, INSN_ADRP);
    
    if (!ref) {
        return 0;
    }
    
    // pc base
    uint64_t val = kerndumpbase;
    
    uint32_t* insn = (uint32_t*)(kernel + ref);
    // add pc (well, offset)
    val += ((uint8_t*)(insn)-kernel) & ~0xfff;
    uint8_t xm = *insn & 0x1f;
    
    // add imm: immhi(bits 23-5)|immlo(bits 30-29)
    val += (*insn << 9 & 0x1ffffc000) | (*insn >> 17 & 0x3000);
    
    ++insn;
    // STR Xn, [Xm,_boottime@PAGEOFF]
    if ((*insn & 0xF9090000) != 0xF9000000) {
        return 0;
    }
    if (((*insn >> 5) & 0x1f) != xm) {
        return 0;
    }
    // add pageoff
    val += ((*insn >> 10) & 0xFFF) << 3;
    
    return val;
}

/*
 *
 *
 *
 */

/*
 *
 * @stek29's patches
 *
 */

addr_t find_zone_map_ref(void)
{
    // \"Nothing being freed to the zone_map. start = end = %p\\n\"
    uint64_t val = kerndumpbase;
    
    addr_t ref = find_strref("\"Nothing being freed to the zone_map. start = end = %p\\n\"", 1, string_base_cstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    // skip add & adrp for panic str
    ref -= 8;
    
    // adrp xX, #_zone_map@PAGE
    ref = step64_back(kernel, ref, 30, INSN_ADRP);
    
    if (!ref) {
        return 0;
    }
    
    uint32_t* insn = (uint32_t*)(kernel + ref);
    // get pc
    val += ((uint8_t*)(insn)-kernel) & ~0xfff;
    uint8_t xm = *insn & 0x1f;
    
    // don't ask, I wrote this at 5am
    val += (*insn << 9 & 0x1ffffc000) | (*insn >> 17 & 0x3000);
    
    // ldr x, [xX, #_zone_map@PAGEOFF]
    ++insn;
    if ((*insn & 0xF9C00000) != 0xF9400000) {
        return 0;
    }
    
    // xd == xX, xn == xX,
    if ((*insn & 0x1f) != xm || ((*insn >> 5) & 0x1f) != xm) {
        return 0;
    }
    
    val += ((*insn >> 10) & 0xFFF) << 3;
    
    return val;
}

addr_t find_OSBoolean_True(void)
{
    addr_t val;
    addr_t ref = find_strref("Delay Autounload", 2, string_base_cstring, false, false);
    if (!ref) ref = find_strref("Delay Autounload", 1, string_base_cstring, false, false);
    
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    
    addr_t weird_instruction = 0;
    for (int i = 4; i < 4 * 0x100; i += 4) {
        uint32_t op = *(uint32_t*)(kernel + ref + i);
        if (op == 0x320003E0) {
            weird_instruction = ref + i;
            break;
        }
    }
    if (!weird_instruction) {
        return 0;
    }
    
    val = calc64(kernel, ref, weird_instruction, 8);
    if (!val) {
        return 0;
    }
    
    return val + kerndumpbase;
}

addr_t find_osunserializexml(void)
{
    addr_t ref = find_strref("OSUnserializeXML: %s near line %d\n", 1, string_base_cstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, xnucore_base, ref);
    
    if (!start) return 0;
    
    if (monolithic_kernel) {
        ref = find_reference(start + kerndumpbase, 1, false);
        if (!ref) return 0;
        ref -= kerndumpbase;
        
        start = bof64(kernel, xnucore_base, ref);
        if (!start) return 0;
    }
    
    return start + kerndumpbase;
}

addr_t find_smalloc(void)
{
    addr_t ref = find_strref("sandbox memory allocation failure", 1, string_base_pstring, false, false);
    if (!ref) ref = find_strref("sandbox memory allocation failure", 1, string_base_oslstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, prelink_base, ref);
    
    if (!start) {
        return 0;
    }
    
    return start + kerndumpbase;
}

addr_t find_shenanigans(void)
{
    addr_t ref = find_strref("\"shenanigans!", 1, string_base_pstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    // find sb_evaluate
    ref = bof64(kernel, prelink_base, ref);
    //printf("sb_evaluate: 0x%llx\n", ref + kerndumpbase);
    
    if (!ref) {
        return 0;
    }
    
    // ADRP Xm, #_is_kernel_cred_kerncred@PAGE
    ref = step64(kernel, ref, 0x100, INSN_ADRP);
    
    if (!ref) {
        return 0;
    }
    
    // pc base
    uint64_t val = kerndumpbase;
    
    uint32_t* insn = (uint32_t*)(kernel + ref);
    // add pc (well, offset)
    val += ((uint8_t*)(insn)-kernel) & ~0xfff;
    uint8_t xm = *insn & 0x1f;
    
    // add imm: immhi(bits 23-5)|immlo(bits 30-29)
    val += (*insn << 9 & 0x1ffffc000) | (*insn >> 17 & 0x3000);
    
    ++insn;
    // LDR Xn, [Xm,#_is_kernel_cred_kerncred@PAGEOFF]
    if ((*insn & 0xF9C00000) != 0xF9400000) {
        return 0;
    }
    if (((*insn >> 5) & 0x1f) != xm) {
        return 0;
    }
    // add pageoff
    val += ((*insn >> 10) & 0xFFF) << 3;
    uint8_t xn = (*insn & 0x1f);
    
    ++insn;
    // CBNZ Xn, ...
    if ((*insn & 0xFC000000) != 0xB4000000) {
        return 0;
    }
    if ((*insn & 0x1f) != xn) {
        return 0;
    }
    
    return val;
}

/*
 *
 *
 *
 */

/*
 *
 * @pwn20wnd's patches
 *
 */

addr_t find_move_snapshot_to_purgatory(void)
{
    addr_t ref = find_strref("move_snapshot_to_purgatory", 1, string_base_pstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, prelink_base, ref);
    
    if (!start) {
        return 0;
    }
    
    return start + kerndumpbase;
}

addr_t find_chgproccnt(void)
{
    addr_t ref = find_strref("\"chgproccnt: lost user\"", 1, string_base_cstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, xnucore_base, ref);
    
    if (!start) {
        return 0;
    }
    
    return start + kerndumpbase;
}

addr_t find_kauth_cred_ref(void)
{
    addr_t ref = find_strref("\"kauth_cred_ref: trying to take a reference on a cred with no references\"", 1, string_base_cstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, xnucore_base, ref);
    
    if (!start) {
        return 0;
    }
    
    return start + kerndumpbase;
}

addr_t find_apfs_jhash_getvnode(void)
{
    addr_t ref = find_strref("apfs_jhash_getvnode", 1, string_base_pstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, prelink_base, ref);
    
    if (!start) {
        return 0;
    }
    
    return start + kerndumpbase;
}

addr_t find_fs_lookup_snapshot_metadata_by_name() {
    uint64_t ref = find_strref("%s:%d: fs_rename_snapshot('%s', %u, '%s', %u) returned %d", 1, string_base_pstring, false, false), func = 0, call = 0;
    if (!ref) return 0;
    
    ref -= kerndumpbase;
    
    for (int i = 0; i < 11; i++) {
        call = step64_back(kernel, ref, 256, INSN_CALL);
        if (!call) return 0;
        
        ref = call - 4;
    }
    
    func = follow_call64(kernel, call);
    if (!func) return 0;
    
    return func + kerndumpbase;
}

addr_t find_fs_lookup_snapshot_metadata_by_name_and_return_name() {
    uint64_t ref = find_strref("%s:%d: fs_rename_snapshot('%s', %u, '%s', %u) returned %d", 1, string_base_pstring, false, false), func = 0, call = 0;
    if (!ref) return 0;
    
    ref -= kerndumpbase;
    
    for (int i = 0; i < 7; i++) {
        call = step64_back(kernel, ref, 256, INSN_CALL);
        if (!call) return 0;
        
        ref = call - 4;
    }
    
    func = follow_call64(kernel, call);
    if (!func) return 0;
    
#ifdef HAVE_MAIN
    // Verify we got the right function
    uint64_t sub = find_fs_lookup_snapshot_metadata_by_name();
    if (!sub) return 0;
    
    call = step64(kernel, ref, 256, INSN_CALL);
    if (!call) return 0;
    
    if (follow_call64(kernel, call) != func) return 0;
#endif
    
    return func + kerndumpbase;
}

addr_t find_mount_common() {
    uint64_t ref = find_strref("\"mount_common():", 1, string_base_cstring, false, false);
    if (!ref) return 0;
    ref -= kerndumpbase;
    uint64_t func = bof64(kernel, xnucore_base, ref);
    if (!func) return 0;
    return func + kerndumpbase;
}


addr_t find_fs_snapshot() {
    uint64_t mount_common = find_mount_common();
    if (!mount_common) return 0;
    
    uint64_t ref = find_reference(mount_common, 5, false);
    if (!ref) return 0;
    ref -= kerndumpbase;
    
    uint64_t func = bof64(kernel, xnucore_base, ref);
    if (!func) return 0;
    return func + kerndumpbase;
}

addr_t find_vnode_get_snapshot() {
    uint64_t fs_snapshot = find_fs_snapshot();
    if (!fs_snapshot) return 0;
    fs_snapshot -= kerndumpbase;
    
    uint64_t call = step64(kernel, fs_snapshot+4, 0x400, 0xAA0003E6, 0xFFE0FFFF);
    if (!call) {
        return 0;
    }
    call += 4;
    uint64_t func = follow_call64(kernel, call);
    if (!func) return 0;
    
#ifdef HAVE_MAIN
    // Verification
    
    int i=0;
    uint64_t ref;
    while ((ref = find_reference(func + kerndumpbase, i+1, false))) {
        if (bof64(kernel, xnucore_base, ref - kerndumpbase) != fs_snapshot) {
            return 0;
        }
        i++;
    }
    if (i==0) return 0;
#endif
    
    return func + kerndumpbase;
}

addr_t find_pmap_load_trust_cache() {
    if (auth_ptrs) {
        addr_t ref = find_strref("%s: trust cache already loaded, ignoring", 2, 0, false, false);
        if (!ref) ref = find_strref("%s: trust cache already loaded, ignoring", 1, 0, false, false);
        if (!ref) return 0;
        
        ref -= kerndumpbase;
        
        addr_t func = step64_back(kernel, ref, 200, INSN_CALL);
        if (!func) return 0;
        
        func -= 4;
        
        func = step64_back(kernel, func, 200, INSN_CALL);
        if (!func) return 0;
        
        func = follow_call64(kernel, func);
        if (!func) return 0;
        
        return func + kerndumpbase;
    }
    addr_t ref = find_strref("\"loadable trust cache buffer too small (%ld) for entries claimed (%d)\"", 1, string_base_cstring, false, true);
    if (!ref) return 0;
    
    ref -= kerndumpbase;
    
    uint64_t start = bof64(kernel, prelink_base, ref);
    
    if (!start) return 0;
    
    return start + kerndumpbase;
}

addr_t find_paciza_pointer__l2tp_domain_module_start() {
    uint64_t string = (uint64_t)boyermoore_horspool_memmem(kernel + data_base, data_size, (const unsigned char *)"com.apple.driver.AppleSynopsysOTGDevice", strlen("com.apple.driver.AppleSynopsysOTGDevice")) - (uint64_t)kernel;
    
    if (!string) {
        return 0;
    }
    
    return string + kerndumpbase - 0x20;
}

addr_t find_paciza_pointer__l2tp_domain_module_stop() {
    uint64_t string = (uint64_t)boyermoore_horspool_memmem(kernel + data_base, data_size, (const unsigned char *)"com.apple.driver.AppleSynopsysOTGDevice", strlen("com.apple.driver.AppleSynopsysOTGDevice")) - (uint64_t)kernel;
    
    if (!string) {
        return 0;
    }
    
    return string + kerndumpbase - 0x18;
}

uint64_t find_l2tp_domain_inited() {
    uint64_t ref = find_strref("L2TP domain init\n", 1, string_base_cstring, false, false);
    
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    
    uint64_t addr = calc64(kernel, ref, ref + 32, 8);
    
    if (!addr) {
        return 0;
    }
    
    return addr + kerndumpbase;
}

uint64_t find_sysctl__net_ppp_l2tp() {
    uint64_t ref = find_strref("L2TP domain terminate : PF_PPP domain does not exist...\n", 1, string_base_cstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    ref += 4;
    
    uint64_t addr = calc64(kernel, ref, ref + 28, 0);
    
    if (!addr) {
        return 0;
    }
    
    return addr + kerndumpbase;
}

uint64_t find_sysctl_unregister_oid() {
    uint64_t ref = find_strref("L2TP domain terminate : PF_PPP domain does not exist...\n", 1, string_base_cstring, false, false);
    
    if (!ref) {
        return 0;
    }
    
    ref -= kerndumpbase;
    
    uint64_t addr = step64(kernel, ref, 28, INSN_CALL);
    
    if (!addr) {
        return 0;
    }
    
    addr += 4;
    addr = step64(kernel, addr, 28, INSN_CALL);
    
    if (!addr) {
        return 0;
    }
    
    uint64_t call = follow_call64(kernel, addr);
    if (!call) {
        return 0;
    }
    return call + kerndumpbase;
}

uint64_t find_mov_x0_x4__br_x5() {
    uint32_t bytes[] = {
        0xaa0403e0, // mov x0, x4
        0xd61f00a0  // br x5
    };
    
    uint64_t addr = (uint64_t)boyermoore_horspool_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) {
        return 0;
    }
    
    return addr - (uint64_t)kernel + kerndumpbase;
}

uint64_t find_mov_x9_x0__br_x1() {
    uint32_t bytes[] = {
        0xaa0003e9, // mov x9, x0
        0xd61f0020  // br x1
    };
    
    uint64_t addr = (uint64_t)boyermoore_horspool_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) {
        return 0;
    }
    
    return addr - (uint64_t)kernel + kerndumpbase;
}

uint64_t find_mov_x10_x3__br_x6() {
    uint32_t bytes[] = {
        0xaa0303ea, // mov x10, x3
        0xd61f00c0  // br x6
    };
    
    uint64_t addr = (uint64_t)boyermoore_horspool_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) {
        return 0;
    }
    
    return addr - (uint64_t)kernel + kerndumpbase;
}

uint64_t find_kernel_forge_pacia_gadget() {
    uint32_t bytes[] = {
        0xdac10149, // paci
        0xf9007849  // str x9, [x2, #240]
    };
    
    uint64_t addr = (uint64_t)boyermoore_horspool_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) {
        return 0;
    }
    
    return addr - (uint64_t)kernel + kerndumpbase;
}

uint64_t find_kernel_forge_pacda_gadget() {
    uint32_t bytes[] = {
        0xdac10949, // pacd x9
        0xf9007449  // str x9, [x2, #232]
    };
    
    uint64_t addr = (uint64_t)boyermoore_horspool_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) {
        return 0;
    }
    
    return addr - (uint64_t)kernel + kerndumpbase;
}

uint64_t find_IOUserClient__vtable() {
    uint64_t ref1 = find_strref("IOUserClient", 2, string_base_cstring, true, false);
    
    if (!ref1) {
        return 0;
    }
    
    ref1 -= kerndumpbase;
    
    uint64_t ref2 = find_strref("IOUserClient", 3, string_base_cstring, true, false);
    
    if (!ref2) {
        return 0;
    }
    
    ref2 -= kerndumpbase;
    
    uint64_t func2 = bof64(kernel, xnucore_base, ref2);
    
    if (!func2) {
        return 0;
    }
    
    uint64_t vtable = calc64(kernel, ref1, func2, 8);
    
    if (!vtable) {
        return 0;
    }
    
    return vtable + kerndumpbase;
}

uint64_t find_IORegistryEntry__getRegistryEntryID() {
    uint32_t bytes[] = {
        0xf9400808, // ldr x8, [x0, #0x10]
    };
    
    uint64_t addr = (uint64_t)boyermoore_horspool_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) {
        return 0;
    }
    
    // basically just look the instructions
    // can't find a better way
    // this was not done like the previous gadgets because an address is being used, which won't be the same between devices so can't be hardcoded and i gotta use masks
    
    // cbz x8, SOME_ADDRESS <= where we do masking (((*(uint32_t *)(addr + 4)) & 0xFC000000) != 0xb4000000)
    // ldr x0, [x8, #8]     <= 2nd part of 0xd65f03c0f9400500
    // ret                  <= 1st part of 0xd65f03c0f9400500
    
    while ((((*(uint32_t *)(addr + 4)) & 0xFC000000) != 0xb4000000) || (*(uint64_t*)(addr + 8) != 0xd65f03c0f9400500)) {
        addr = (uint64_t)boyermoore_horspool_memmem((unsigned char *)(addr + 4), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    }
    
    return addr + kerndumpbase - (uint64_t)kernel;;
}

/*
 *
 *
 *
 */

#ifndef NOT_DARWIN
#include <mach-o/nlist.h>
#else
#include "mach-o_nlist.h"
#endif


addr_t
find_symbol(const char *symbol)
{
    if (!symbol) {
        return 0;
    }
    
    unsigned i;
    const struct mach_header *hdr = kernel_mh;
    const uint8_t *q;
    int is64 = 0;
    
    if (IS64(hdr)) {
        is64 = 4;
    }
    
    /* XXX will only work on a decrypted kernel */
    if (!kernel_delta) {
        return 0;
    }
    
    /* XXX I should cache these.  ohwell... */
    q = (uint8_t *)(hdr + 1) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SYMTAB) {
            const struct symtab_command *sym = (struct symtab_command *)q;
            const char *stroff = (const char *)kernel + sym->stroff + kernel_delta;
            if (is64) {
                uint32_t k;
                const struct nlist_64 *s = (struct nlist_64 *)(kernel + sym->symoff + kernel_delta);
                for (k = 0; k < sym->nsyms; k++) {
                    if (s[k].n_type & N_STAB) {
                        continue;
                    }
                    if (s[k].n_value && (s[k].n_type & N_TYPE) != N_INDR) {
                        if (!strcmp(symbol, stroff + s[k].n_un.n_strx)) {
                            /* XXX this is an unslid address */
                            return s[k].n_value;
                        }
                    }
                }
            }
        }
        q = q + cmd->cmdsize;
    }
    return 0;
}

#ifdef HAVE_MAIN

int
main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: patchfinder64 _decompressed_kernel_image_\n");
        printf("iOS ARM64 kernel patchfinder\n");
        exit(EXIT_FAILURE);
    }
    if (access(argv[1], F_OK) != 0) {
        printf("%s: %s\n", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }
    int rv;
    addr_t kernel_base = 0;
    const addr_t vm_kernel_slide = 0;
    if (init_kernel(NULL, kernel_base, argv[1]) != 0) {
        printf("Failed to prepare kernel\n");
        exit(EXIT_FAILURE);
    }
    
#define FIND(name) do { \
addr_t patchfinder_offset = find_ ##name (); \
printf("%s: PF=0x%llx - %s\n", #name, patchfinder_offset, (patchfinder_offset != 0 && patchfinder_offset != kerndumpbase)? "PASS" : "FAIL"); \
} while(false)
#define CHECK(name) do { \
addr_t actual_offset = find_symbol("_" #name); \
if (actual_offset == 0) { \
FIND(name); \
} else { \
addr_t patchfinder_offset = find_ ##name (); \
printf("%s: PF=0x%llx - AS=0x%llx - %s\n", #name, patchfinder_offset, actual_offset, ((actual_offset==0?patchfinder_offset!=0:patchfinder_offset == actual_offset) ? "PASS" : "FAIL")); \
} \
} while(false)
    
    CHECK(vfs_context_current);
    CHECK(vnode_lookup);
    CHECK(vnode_put);
    CHECK(vnode_getfromfd);
    CHECK(vnode_getattr);
    CHECK(SHA1Init);
    CHECK(SHA1Update);
    CHECK(SHA1Final);
    CHECK(csblob_entitlements_dictionary_set);
    CHECK(kernel_task);
    CHECK(kernproc);
    CHECK(vnode_recycle);
    CHECK(lck_mtx_lock);
    CHECK(lck_mtx_unlock);
    CHECK(strlen);
    CHECK(add_x0_x0_0x40_ret);
    CHECK(trustcache);
    CHECK(move_snapshot_to_purgatory);
    CHECK(apfs_jhash_getvnode);
    CHECK(zone_map_ref);
    CHECK(OSBoolean_True);
    CHECK(osunserializexml);
    CHECK(smalloc);
    CHECK(shenanigans);
    CHECK(fs_lookup_snapshot_metadata_by_name_and_return_name);
    CHECK(mount_common);
    CHECK(fs_snapshot);
    CHECK(vnode_get_snapshot);
    CHECK(boottime);
    if (auth_ptrs) {
        CHECK(paciza_pointer__l2tp_domain_module_start);
        CHECK(paciza_pointer__l2tp_domain_module_stop);
        CHECK(l2tp_domain_inited);
        CHECK(sysctl__net_ppp_l2tp);
        CHECK(sysctl_unregister_oid);
        CHECK(mov_x0_x4__br_x5);
        CHECK(mov_x9_x0__br_x1);
        CHECK(mov_x10_x3__br_x6);
        CHECK(kernel_forge_pacia_gadget);
        CHECK(kernel_forge_pacda_gadget);
        CHECK(pmap_load_trust_cache);
    }
    CHECK(IOUserClient__vtable);
    CHECK(IORegistryEntry__getRegistryEntryID);
    
    term_kernel();
    return EXIT_SUCCESS;
}

#endif    /* HAVE_MAIN */
