#include <string.h>

int check_user(const char* username, const char* password) {
    // Example logic: In real usage, check against a database!
    if (strcmp(username, "user") == 0 && strcmp(password, "pass") == 0) {
        return 1; // success
    }
    return 0; // failure
}
