#include "include/elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// 헥사 출력 함수
void print_hex(byte* mem, uint32 n) {
    for (uint32 i = 0; i < n; ++i) {
        printf("%02x ", mem[i]);
        if (i > 0 && i % 16 == 15) printf("\n");
    }
    printf("\n");
}

// ELF 파일 읽기
byte* read_elf(const char* filename, uint32* length) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return NULL;
    }

    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) {
        perror("lseek");
        close(fd);
        return NULL;
    }
    lseek(fd, 0, SEEK_SET);

    *length = (uint32)file_size;
    byte* elf_file = (byte*)malloc(*length);
    if (!elf_file) {
        perror("malloc");
        close(fd);
        return NULL;
    }

    ssize_t bytes_read = read(fd, elf_file, *length);
    if (bytes_read != *length) {
        perror("read");
        free(elf_file);
        close(fd);
        return NULL;
    }

    close(fd);
    return elf_file;
}

// ELF 헤더 읽기
Elf64_Ehdr* read_elf_header(byte* elf_file) {
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
    if (!elf_header) {
        perror("malloc");
        return NULL;
    }
    memcpy(elf_header, elf_file, sizeof(Elf64_Ehdr));
    return elf_header;
}

// 섹션 헤더 읽기
Elf64_Shdr** read_section_headers(byte* elf_file, Elf64_Ehdr* elf_header) {
    uint64 offset = elf_header->e_shoff;
    uint32 n_headers = elf_header->e_shnum;
    Elf64_Shdr** section_headers = (Elf64_Shdr**)malloc(sizeof(Elf64_Shdr*) * n_headers);
    if (!section_headers) {
        perror("malloc");
        return NULL;
    }

    for (uint32 i = 0; i < n_headers; ++i) {
        section_headers[i] = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr));
        if (!section_headers[i]) {
            perror("malloc");
            // 메모리 해제 필요
            for (uint32 j = 0; j < i; ++j) {
                free(section_headers[j]);
            }
            free(section_headers);
            return NULL;
        }
        memcpy(section_headers[i], elf_file + offset + i * elf_header->e_shentsize, sizeof(Elf64_Shdr));
    }

    return section_headers;
}

// 섹션 헤더 문자열 테이블 가져오기
byte* get_section_header_string_table(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header) {
    uint32 shstrndx = elf_header->e_shstrndx;
    if (shstrndx >= elf_header->e_shnum) {
        fprintf(stderr, "Invalid section header string table index.\n");
        return NULL;
    }

    uint64 offset = section_headers[shstrndx]->sh_offset;
    uint64 size = section_headers[shstrndx]->sh_size;

    byte* sh_strtab = (byte*)malloc(size);
    if (!sh_strtab) {
        perror("malloc");
        return NULL;
    }

    memcpy(sh_strtab, elf_file + offset, size);
    return sh_strtab;
}

// 심볼 테이블 가져오기
Elf64_Sym** get_symbol_table(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header) {
    uint32 idx_symtab_header = -1;
    Elf64_Sym** symbol_table = NULL;

    for (uint32 i = 0; i < elf_header->e_shnum; ++i) {
        if (section_headers[i]->sh_type == SHT_SYMTAB) {
            idx_symtab_header = i;
            break;
        }
    }

    if (idx_symtab_header == -1) {
        printf("No symbol table found.\n");
        return NULL;
    }

    uint64 offset = section_headers[idx_symtab_header]->sh_offset;
    uint64 size = section_headers[idx_symtab_header]->sh_size;
    uint32 n_symbols = size / sizeof(Elf64_Sym);

    symbol_table = (Elf64_Sym **)malloc(sizeof(Elf64_Sym*) * n_symbols);
    if (!symbol_table) {
        perror("malloc");
        return NULL;
    }

    for (uint32 i = 0; i < n_symbols; ++i) {
        symbol_table[i] = (Elf64_Sym*)malloc(sizeof(Elf64_Sym));
        if (!symbol_table[i]) {
            perror("malloc");
            // 메모리 해제 필요
            for (uint32 j = 0; j < i; ++j) {
                free(symbol_table[j]);
            }
            free(symbol_table);
            return NULL;
        }
        memcpy(symbol_table[i], elf_file + offset + i * sizeof(Elf64_Sym), sizeof(Elf64_Sym));
    }

    return symbol_table;
}

// 심볼 문자열 테이블 가져오기
byte* get_symbol_string_table(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header) {
    uint32 idx_symtab_header = -1;

    for (uint32 i = 0; i < elf_header->e_shnum; ++i) {
        if (section_headers[i]->sh_type == SHT_SYMTAB) {
            idx_symtab_header = i;
            break;
        }
    }

    if (idx_symtab_header == -1) {
        printf("No symbol table found.\n");
        return NULL;
    }

    uint32 link = section_headers[idx_symtab_header]->sh_link;
    if (link >= elf_header->e_shnum) {
        fprintf(stderr, "Invalid link index for symbol string table.\n");
        return NULL;
    }

    uint64 offset = section_headers[link]->sh_offset;
    uint64 size = section_headers[link]->sh_size;

    byte* symbol_strtab = (byte*)malloc(size);
    if (!symbol_strtab) {
        perror("malloc");
        return NULL;
    }

    memcpy(symbol_strtab, elf_file + offset, size);
    return symbol_strtab;
}

// 동적 섹션 가져오기
Elf64_Dyn** get_dynamic_section(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header, uint32* dyn_count) { 
    Elf64_Dyn** dynamic_section = NULL;
    uint32 idx_dynamic = -1;

    for (uint32 i = 0; i < elf_header->e_shnum; ++i) {
        if (section_headers[i]->sh_type == SHT_DYNAMIC) {
            idx_dynamic = i;
            break;
        }
    }

    if (idx_dynamic == -1) {
        printf("No dynamic section found.\n");
        *dyn_count = 0;
        return NULL;
    }

    uint64 offset = section_headers[idx_dynamic]->sh_offset;
    uint64 size = section_headers[idx_dynamic]->sh_size;
    *dyn_count = size / sizeof(Elf64_Dyn);

    dynamic_section = (Elf64_Dyn**)malloc(sizeof(Elf64_Dyn*) * (*dyn_count));
    if (!dynamic_section) {
        perror("malloc");
        *dyn_count = 0;
        return NULL;
    }

    for (uint32 i = 0; i < *dyn_count; ++i) {
        dynamic_section[i] = (Elf64_Dyn*)malloc(sizeof(Elf64_Dyn));
        if (!dynamic_section[i]) {
            perror("malloc");
            // 메모리 해제 필요
            for (uint32 j = 0; j < i; ++j) {
                free(dynamic_section[j]);
            }
            free(dynamic_section);
            *dyn_count = i;
            return NULL;
        }
        memcpy(dynamic_section[i], elf_file + offset + i * sizeof(Elf64_Dyn), sizeof(Elf64_Dyn));
    }

    return dynamic_section;
}

// 동적 문자열 테이블 가져오기
byte* get_dynamic_string_table(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header) {
    uint32 idx_dynamic = -1;

    for (uint32 i = 0; i < elf_header->e_shnum; ++i) {
        if (section_headers[i]->sh_type == SHT_DYNAMIC) {
            idx_dynamic = i;
            break;
        }
    }

    if (idx_dynamic == -1) {
        printf("No dynamic section found.\n");
        return NULL;
    }

    uint32 link = section_headers[idx_dynamic]->sh_link;
    if (link >= elf_header->e_shnum) {
        fprintf(stderr, "Invalid link index for dynamic string table.\n");
        return NULL;
    }

    uint64 offset = section_headers[link]->sh_offset;
    uint64 size = section_headers[link]->sh_size;

    byte* dynamic_strtab = (byte*)malloc(size);
    if (!dynamic_strtab) {
        perror("malloc");
        return NULL;
    }

    memcpy(dynamic_strtab, elf_file + offset, size);
    return dynamic_strtab;
}

// 프로그램 헤더 읽기
Elf64_Phdr** read_program_headers(byte* elf_file, Elf64_Ehdr* elf_header) {
    uint64 offset = elf_header->e_phoff;
    uint16 n_headers = elf_header->e_phnum;
    Elf64_Phdr** program_headers = NULL;

    if (n_headers == 0) {
        printf("No program headers found.\n");
        return NULL;
    }

    program_headers = (Elf64_Phdr**)malloc(sizeof(Elf64_Phdr*) * n_headers);
    if (!program_headers) {
        perror("malloc");
        return NULL;
    }

    for (uint16 i = 0; i < n_headers; ++i) {
        program_headers[i] = (Elf64_Phdr*)malloc(sizeof(Elf64_Phdr));
        if (!program_headers[i]) {
            perror("malloc");
            // 메모리 해제 필요
            for (uint16 j = 0; j < i; ++j) {
                free(program_headers[j]);
            }
            free(program_headers);
            return NULL;
        }
        memcpy(program_headers[i], elf_file + offset + i * sizeof(Elf64_Phdr), sizeof(Elf64_Phdr));
    }

    return program_headers;
}

// ELF 헤더 출력
void print_elf_header(Elf64_Ehdr* elf_header) {
    printf("* ELF Header\n");
    printf("Magic:\t");
    for (int i = 0; i < EI_NIDENT; ++i) {
        printf("%02x ", elf_header->e_ident[i]);
    }
    printf("\n");

    printf("Type:\t%d\n", elf_header->e_type);
    printf("Machine:\t%d\n", elf_header->e_machine);
    printf("Version:\t%d\n", elf_header->e_version);
    printf("Entry:\t0x%lx\n", elf_header->e_entry);
    printf("Program header offset:\t0x%lx\n", elf_header->e_phoff);
    printf("Section header offset:\t0x%lx\n", elf_header->e_shoff);
    printf("Flags:\t0x%x\n", elf_header->e_flags);
    printf("ELF header size:\t%d\n", elf_header->e_ehsize);
    printf("Program header entry size:\t%d\n", elf_header->e_phentsize);
    printf("Number of program headers:\t%d\n", elf_header->e_phnum);
    printf("Section header entry size:\t%d\n", elf_header->e_shentsize);
    printf("Number of section headers:\t%d\n", elf_header->e_shnum);
    printf("Section header string table index:\t%d\n", elf_header->e_shstrndx);
    printf("\n");
}

// 섹션 헤더 출력
void print_section_headers(Elf64_Shdr** section_headers, byte* section_header_string_table, Elf64_Ehdr* elf_header) {
    uint32 n_headers = elf_header->e_shnum;

    printf("* Section headers\n");
    printf("Idx Name\t\t\tSize\t\tAddr\t\tOffset\t\tType\n");

    for (uint32 i = 0; i < n_headers; ++i) {
        if (i == 0) continue;

        uint32 name = section_headers[i]->sh_name;
        uint64 size = section_headers[i]->sh_size;
        uint64 addr = section_headers[i]->sh_addr;
        uint64 offset = section_headers[i]->sh_offset;
        uint32 type = section_headers[i]->sh_type;
        uint32 link = section_headers[i]->sh_link;

        printf("%2d %s\t%08llx\t%016llx\t%08llx\t", 
               i, 
               section_header_string_table + name, 
               size, 
               addr, 
               offset);

        switch (type) {
            case SHT_PROGBITS: printf("SHT_PROGBITS\n"); break;
            case SHT_SYMTAB: 
                printf("SHT_SYMTAB(%x)\n", link); 
                break;
            case SHT_STRTAB: printf("SHT_STRTAB\n"); break;
            case SHT_RELA: printf("SHT_RELA\n"); break;
            case SHT_HASH: printf("SHT_HASH\n"); break;
            case SHT_DYNAMIC: printf("SHT_DYNAMIC\n"); break;
            case SHT_NOTE: printf("SHT_NOTE\n"); break;
            case SHT_NOBITS: printf("SHT_NOBITS\n"); break;
            case SHT_REL: printf("SHT_REL\n"); break;
            case SHT_SHLIB: printf("SHT_SHLIB\n"); break;
            case SHT_DYNSYM: printf("SHT_DYNSYM\n"); break;
            default:
                printf("UNKNOWN\n");
        }
    }

    printf("\n");
}

// 심볼 테이블 출력
void print_symbol_table(Elf64_Shdr** section_headers, byte* section_header_string_table, Elf64_Sym** symbol_table, byte* symbol_string_table, Elf64_Ehdr* elf_header) {
    uint32 idx_symtab_header = -1;

    for (uint32 i = 0; i < elf_header->e_shnum; ++i) {
        if (section_headers[i]->sh_type == SHT_SYMTAB) {
            idx_symtab_header = i;
            break;
        }
    }

    if (idx_symtab_header == -1) {
        printf("No symbol table found.\n");
        return;
    }

    uint64 size = section_headers[idx_symtab_header]->sh_size;
    uint32 n_symbols = size / sizeof(Elf64_Sym);

    printf("* Symbol table\n");
    printf("Num:\tSection\t\t\tValue\t\tSize\t\tName\n");

    for (uint32 i = 0; i < n_symbols; ++i) {
        uint32 name = symbol_table[i]->st_name;
        uint64 value = symbol_table[i]->st_value;
        uint64 size_sym = symbol_table[i]->st_size;
        uint16 shndx = symbol_table[i]->st_shndx;
        Elf64_Shdr* section_header = (shndx < elf_header->e_shnum) ? section_headers[shndx] : NULL;
        uint32 sh_name = section_header != NULL ? section_header->sh_name : 0;
        byte* section_name = section_header != NULL ? (section_header_string_table + sh_name) : "*ABS*";

        if (name == 0) continue;

        printf("%d\t%s\t\t0x%016llx\t%llu\t\t%s\n", 
               i, 
               section_name, 
               value, 
               size_sym, 
               symbol_string_table + name);
    }

    printf("\n");
}

// 동적 섹션 출력
void print_dynamic_section(Elf64_Shdr** section_headers, Elf64_Dyn** dynamic_section, byte* dynamic_string, Elf64_Ehdr* elf_header, uint32 dyn_count) {
    uint32 idx_dynamic = -1;

    for (uint32 i = 0; i < elf_header->e_shnum; ++i) {
        if (section_headers[i]->sh_type == SHT_DYNAMIC) {
            idx_dynamic = i;
            break;
        }
    }

    if (idx_dynamic == -1) {
        printf("No dynamic section found.\n");
        return;
    }

    printf("* Dynamic section\n");

    for (uint32 i = 0; i < dyn_count; ++i) {
        sint64 tag = dynamic_section[i]->d_tag;
        uint64 val_ptr;
        printf("%2d\t", i);

        switch(tag) {
            case DT_NEEDED: 
                printf("NEEDED\t"); 
                val_ptr = dynamic_section[i]->d_un.d_val;
                printf("%s", &dynamic_string[val_ptr]);
                break;
            case DT_INIT: printf("INIT\t"); break;
            case DT_FINI: printf("FINI\t"); break;
            case DT_INIT_ARRAY: printf("INIT_ARRAY\t"); break;
            case DT_INIT_ARRAYSZ: printf("INIT_ARRAYSZ\t"); break;
            case DT_FINI_ARRAY: printf("FINI_ARRAY\t"); break;
            case DT_FINI_ARRAYSZ: printf("FINI_ARRAYSZ\t"); break;
            case DT_GNU_HASH: printf("GNU_HASH\t"); break;
            case DT_STRTAB: printf("STRTAB\t"); break;
            case DT_SYMTAB: printf("SYMTAB\t"); break;
            case DT_STRSZ: printf("STRSZ\t"); break;
            case DT_SYMENT: printf("SYMENT\t"); break;
            case DT_DEBUG: printf("DEBUG\t"); break;
            case DT_PLTGOT: printf("PLTGOT\t"); break;
            case DT_PLTRELSZ: printf("PLTRELSZ\t"); break;
            case DT_PLTREL: printf("PLTREL\t"); break;
            case DT_JMPREL: printf("JMPREL\t"); break;
            case DT_RELA: printf("RELA\t"); break;
            case DT_RELASZ: printf("RELASZ\t"); break;
            case DT_RELAENT: printf("RELAENT\t"); break;
            case DT_FLAGS: printf("FLAGS\t"); break;
            case DT_FLAGS_1: printf("FLAGS_1\t"); break;
            case DT_VERNEED: printf("VERNEED\t"); break;
            case DT_VERNEEDNUM: printf("VERNEEDNUM\t"); break;
            case DT_VERSYM: printf("VERSYM\t"); break;
            case DT_RELACOUNT: printf("RELACOUNT\t"); break;
            default: printf("UNKNOWN\t"); break;
        }

        printf("\n");
    }

    printf("\n");
}

// 프로그램 헤더 출력
void print_program_headers(Elf64_Phdr** program_headers, Elf64_Ehdr* elf_header) {
    uint16 n_headers = elf_header->e_phnum;

    printf("* Program headers\n");
    for (uint16 i = 0; i < n_headers; ++i) {
        bool skip = false;
        uint32 type = program_headers[i]->p_type;
        uint32 flags = program_headers[i]->p_flags;
        uint64 offset = program_headers[i]->p_offset;
        uint64 vaddr = program_headers[i]->p_vaddr;
        uint64 paddr = program_headers[i]->p_paddr;
        uint64 filesz = program_headers[i]->p_filesz;
        uint64 memsz = program_headers[i]->p_memsz;
        uint64 align = program_headers[i]->p_align;

        if (type == PT_NULL) continue;

        switch (type) {
            case PT_LOAD: printf("\tLOAD\t"); break;
            case PT_DYNAMIC: printf("\tDYNAMIC\t"); break;
            case PT_INTERP: printf("\tINTERP\t"); break;
            case PT_NOTE: printf("\tNOTE\t"); break;
            case PT_SHLIB: printf("\tSHLIB\t"); break;
            case PT_PHDR: printf("\tPHDR\t"); break;
            default: skip = true; break;
        }

        if (skip) continue;

        printf("off\t0x%016llx\tvaddr\t0x%016llx\tpaddr\t0x%016llx\talign\t0x%llx\n", 
               offset, vaddr, paddr, align);
        printf("\t\tfilesz\t0x%016llx\tmemsz\t0x%016llx\tflags\t", 
               filesz, memsz);
        switch (flags) {
            case 0: printf("---"); break;
            case 1: printf("--x"); break;
            case 2: printf("-w-"); break;
            case 3: printf("-wx"); break;
            case 4: printf("r--"); break;
            case 5: printf("r-x"); break;
            case 6: printf("rw-"); break;
            case 7: printf("rwx"); break;
            default: printf("UNKNOWN"); break;
        }
        printf("\n");
    }
    printf("\n");
}

// 메모리 해제 함수
void free_all(ELF_Info* elf_info) {
    if (!elf_info) return;

    if (elf_info->elf_file) free(elf_info->elf_file);
    if (elf_info->elf_header) free(elf_info->elf_header);
    
    if (elf_info->section_headers) {
        for (uint32 i = 0; i < elf_info->elf_header->e_shnum; ++i) {
            if (elf_info->section_headers[i]) free(elf_info->section_headers[i]);
        }
        free(elf_info->section_headers);
    }

    if (elf_info->section_header_string_table) free(elf_info->section_header_string_table);

    if (elf_info->symbol_table) {
        uint32 idx_symtab_header = -1;
        for (uint32 i = 0; i < elf_info->elf_header->e_shnum; ++i) {
            if (elf_info->section_headers[i]->sh_type == SHT_SYMTAB) {
                idx_symtab_header = i;
                break;
            }
        }
        uint32 n_symbols = (idx_symtab_header != -1) ? 
            elf_info->section_headers[idx_symtab_header]->sh_size / sizeof(Elf64_Sym) : 0;

        for (uint32 i = 0; i < n_symbols; ++i) {
            if (elf_info->symbol_table[i]) free(elf_info->symbol_table[i]);
        }
        free(elf_info->symbol_table);
    }

    if (elf_info->symbol_string_table) free(elf_info->symbol_string_table);

    if (elf_info->dynamic_section) {
        for (uint32 i = 0; i < elf_info->dynamic_count; ++i) {
            if (elf_info->dynamic_section[i]) free(elf_info->dynamic_section[i]);
        }
        free(elf_info->dynamic_section);
    }

    if (elf_info->dynamic_string_table) free(elf_info->dynamic_string_table);

    if (elf_info->program_headers) {
        for (uint32 i = 0; i < elf_info->elf_header->e_phnum; ++i) {
            if (elf_info->program_headers[i]) free(elf_info->program_headers[i]);
        }
        free(elf_info->program_headers);
    }

    free(elf_info);
}
