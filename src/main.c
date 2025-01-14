#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s [target elf]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // ELF_Info 구조체 초기화
    ELF_Info* elf_info = (ELF_Info*)malloc(sizeof(ELF_Info));
    if (!elf_info) {
        perror("malloc");
        return EXIT_FAILURE;
    }
    memset(elf_info, 0, sizeof(ELF_Info));

    // ELF 파일 읽기
    elf_info->elf_file = read_elf(argv[1], &elf_info->length);
    if (!elf_info->elf_file) {
        free(elf_info);
        return EXIT_FAILURE;
    }

    // ELF 헤더 읽기
    elf_info->elf_header = read_elf_header(elf_info->elf_file);
    if (!elf_info->elf_header) {
        free_all(elf_info);
        return EXIT_FAILURE;
    }

    // ELF 헤더 출력
    print_elf_header(elf_info->elf_header);

    // 섹션 헤더 읽기
    elf_info->section_headers = read_section_headers(elf_info->elf_file, elf_info->elf_header);
    if (!elf_info->section_headers) {
        free_all(elf_info);
        return EXIT_FAILURE;
    }

    // 섹션 헤더 문자열 테이블 가져오기
    elf_info->section_header_string_table = get_section_header_string_table(elf_info->elf_file, elf_info->section_headers, elf_info->elf_header);
    if (!elf_info->section_header_string_table) {
        free_all(elf_info);
        return EXIT_FAILURE;
    }

    // 섹션 헤더 출력
    print_section_headers(elf_info->section_headers, elf_info->section_header_string_table, elf_info->elf_header);

    // 심볼 테이블 읽기
    elf_info->symbol_table = get_symbol_table(elf_info->elf_file, elf_info->section_headers, elf_info->elf_header);
    if (elf_info->symbol_table) {
        // 심볼 문자열 테이블 가져오기
        elf_info->symbol_string_table = get_symbol_string_table(elf_info->elf_file, elf_info->section_headers, elf_info->elf_header);
        if (elf_info->symbol_string_table) {
            // 심볼 테이블 출력
            print_symbol_table(elf_info->section_headers, elf_info->section_header_string_table, elf_info->symbol_table, elf_info->symbol_string_table, elf_info->elf_header);
        }
    }

    // 동적 섹션 읽기
    elf_info->dynamic_section = get_dynamic_section(elf_info->elf_file, elf_info->section_headers, elf_info->elf_header, &elf_info->dynamic_count);
    if (elf_info->dynamic_section) {
        // 동적 문자열 테이블 가져오기
        elf_info->dynamic_string_table = get_dynamic_string_table(elf_info->elf_file, elf_info->section_headers, elf_info->elf_header);
        if (elf_info->dynamic_string_table) {
            // 동적 섹션 출력
            print_dynamic_section(elf_info->section_headers, elf_info->dynamic_section, elf_info->dynamic_string_table, elf_info->elf_header, elf_info->dynamic_count);
        }
    }

    // 프로그램 헤더 읽기
    elf_info->program_headers = read_program_headers(elf_info->elf_file, elf_info->elf_header);
    if (elf_info->program_headers) {
        // 프로그램 헤더 출력
        print_program_headers(elf_info->program_headers, elf_info->elf_header);
    }

    // 모든 메모리 해제
    free_all(elf_info);

    return EXIT_SUCCESS;
}