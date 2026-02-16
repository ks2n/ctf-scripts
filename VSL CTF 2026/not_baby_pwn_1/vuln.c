#include <stdio.h>
#include <unistd.h>

int main() {
    char buf[0x500];

    printf("> ");
    read(0, buf, 0x4ffu);
    printf(buf);

    printf("> ");
    read(0, buf, 0x4ffu);
    printf(buf);

    return 0;
}
