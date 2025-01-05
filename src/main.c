#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

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

    // ELF 파일 열기
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        free(elf_info);
        return EXIT_FAILURE;
    }

    // ELF 파일 크기 구하기
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) {
        perror("lseek");
        close(fd);
        free(elf_info);
        return EXIT_FAILURE;
    }
    lseek(fd, 0, SEEK_SET);

    elf_info->length = (uint32)file_size;
    elf_info->elf_file = (byte*)malloc(elf_info->length);
    if (!elf_info->elf_file) {
        perror("malloc");
        close(fd);
        free(elf_info);
        return EXIT_FAILURE;
    }

    ssize_t bytes_read = read(fd, elf_info->elf_file, elf_info->length);
    if (bytes_read != elf_info->length) {
        perror("read");
        free(elf_info->elf_file);
        close(fd);
        free(elf_info);
        return EXIT_FAILURE;
    }

    // ELF 헤더 읽기
    Elf32_Ehdr* elf_header32 = (Elf32_Ehdr*)elf_info->elf_file;
    bool is64 = is64Bit(*elf_header32);
    if(is64) {
        elf_info->elf_header = (Elf64_Ehdr*)read_elf_header(elf_info->elf_file);
        if (!elf_info->elf_header) {
            free_all(elf_info);
            close(fd);
            return EXIT_FAILURE;
        }
    } else {
        printf("32-bit ELF 파일은 현재 지원되지 않습니다.\n");
        free(elf_info->elf_file);
        close(fd);
        free(elf_info);
        return EXIT_FAILURE;
    }

    // ELF 헤더 출력
    print_elf_header64(*elf_info->elf_header);

    // 섹션 헤더 읽기
    // ELF 파일을 메모리에 읽어들였으므로, 파일 디스크립터를 통해 읽을 필요가 없습니다.
    // 따라서, 메모리 버퍼에서 직접 섹션 헤더를 파싱하도록 함수들을 수정해야 합니다.
    // 현재 예시에서는 파일 디스크립터를 사용하므로, 이를 메모리 버퍼로 대체하는 것이 필요합니다.

    // 예를 들어, 섹션 헤더를 메모리 버퍼에서 직접 파싱하는 함수를 구현할 수 있습니다.

    // 섹션 헤더 테이블 포인터 계산
    Elf64_Shdr* sh_table = (Elf64_Shdr*)(elf_info->elf_file + elf_info->elf_header->e_shoff);
    elf_info->section_headers = (Elf64_Shdr**)malloc(sizeof(Elf64_Shdr*) * elf_info->elf_header->e_shnum);
    if (!elf_info->section_headers) {
        perror("malloc");
        free_all(elf_info);
        close(fd);
        return EXIT_FAILURE;
    }

    for(uint32 i = 0; i < elf_info->elf_header->e_shnum; i++) {
        elf_info->section_headers[i] = &sh_table[i];
    }

    // 섹션 헤더 문자열 테이블 가져오기
    elf_info->section_header_string_table = (byte*)(elf_info->elf_file + sh_table[elf_info->elf_header->e_shstrndx].sh_offset);
    if (!elf_info->section_header_string_table) {
        fprintf(stderr, "Failed to get section header string table.\n");
        free_all(elf_info);
        close(fd);
        return EXIT_FAILURE;
    }

    // 섹션 헤더 출력
    print_section_headers64(elf_info->elf_header, elf_info->section_headers, elf_info->section_header_string_table);

    // 심볼 테이블 출력
    print_symbols64(elf_info->elf_file, elf_info->elf_header, elf_info->section_headers);

    // 동적 섹션 출력
    // 동적 섹션을 처리하는 추가적인 코드가 필요합니다.

    // 프로그램 헤더 출력
    // 프로그램 헤더도 메모리 버퍼에서 직접 접근하여 출력하도록 수정해야 합니다.

    // 모든 메모리 해제
    free_all(elf_info);
    close(fd);

    return EXIT_SUCCESS;
}
