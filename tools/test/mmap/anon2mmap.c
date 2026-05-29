#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define GB ((long long) 1024 * 1024 * 1024)

int main() {
	long long size = 4 * GB;  // 尝试映射4GB

	void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap failed");
		return 1;
	}
	printf("mmap addr = 0x%lx\n", ptr);

	/* 填充数据以触发实际内存分配 */
	for (long long i = 0; i < size; i += 4096) {
		((char *)ptr)[i] = 'A';
		if (i % (GB) == 0) {
			printf("Allocated %lld GB\n", i / GB);
		}
	}
	printf("Successfully mapped %lld GB\n", size / GB);
	munmap(ptr, size);
	return 0;
}
