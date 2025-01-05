#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <stdint.h>
#include <elf.h>
#include <stdbool.h>

// 타입 정의
typedef uint8_t byte;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef int64_t sint64;

// ELF 구조체들
typedef struct {
    byte* elf_file;
    uint32 length;
    Elf64_Ehdr* elf_header;
    Elf64_Shdr** section_headers;
    byte* section_header_string_table;
    Elf64_Sym** symbol_table;
    byte* symbol_string_table;
    Elf64_Dyn** dynamic_section;
    byte* dynamic_string_table;
    Elf64_Phdr** program_headers;
    uint32 dynamic_count;
} ELF_Info;

// 함수 선언
byte* read_elf(const char* filename, uint32* length);
Elf64_Ehdr* read_elf_header(byte* elf_file);
Elf64_Shdr** read_section_headers(byte* elf_file, Elf64_Ehdr* elf_header);
byte* get_section_header_string_table(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header);
Elf64_Sym** get_symbol_table(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header);
byte* get_symbol_string_table(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header);
Elf64_Dyn** get_dynamic_section(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header, uint32* dyn_count);
byte* get_dynamic_string_table(byte* elf_file, Elf64_Shdr** section_headers, Elf64_Ehdr* elf_header);
Elf64_Phdr** read_program_headers(byte* elf_file, Elf64_Ehdr* elf_header);

// 출력 함수
void print_hex(byte* mem, uint32 n);
void print_elf_header(Elf64_Ehdr* elf_header);
void print_section_headers(Elf64_Shdr** section_headers, byte* section_header_string_table, Elf64_Ehdr* elf_header);
void print_symbol_table(Elf64_Shdr** section_headers, byte* section_header_string_table, Elf64_Sym** symbol_table, byte* symbol_string_table, Elf64_Ehdr* elf_header);
void print_dynamic_section(Elf64_Shdr** section_headers, Elf64_Dyn** dynamic_section, byte* dynamic_string, Elf64_Ehdr* elf_header, uint32 dyn_count);
void print_program_headers(Elf64_Phdr** program_headers, Elf64_Ehdr* elf_header);

// 메모리 해제 함수
void free_all(ELF_Info* elf_info);

#endif // ELF_PARSER_H
