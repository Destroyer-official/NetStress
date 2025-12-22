/**
 * Simple C Unit Testing Framework
 * Minimal testing framework for C driver functions
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Test statistics */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Color codes for output */
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

/* Test macros */
#define TEST_ASSERT(condition, message) \
    do { \
        tests_run++; \
        if (condition) { \
            tests_passed++; \
            printf(COLOR_GREEN "✓" COLOR_RESET " %s\n", message); \
        } else { \
            tests_failed++; \
            printf(COLOR_RED "✗" COLOR_RESET " %s (line %d)\n", message, __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_EQ(actual, expected, message) \
    do { \
        tests_run++; \
        if ((actual) == (expected)) { \
            tests_passed++; \
            printf(COLOR_GREEN "✓" COLOR_RESET " %s\n", message); \
        } else { \
            tests_failed++; \
            printf(COLOR_RED "✗" COLOR_RESET " %s: expected %ld, got %ld (line %d)\n", \
                   message, (long)(expected), (long)(actual), __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_NEQ(actual, not_expected, message) \
    do { \
        tests_run++; \
        if ((actual) != (not_expected)) { \
            tests_passed++; \
            printf(COLOR_GREEN "✓" COLOR_RESET " %s\n", message); \
        } else { \
            tests_failed++; \
            printf(COLOR_RED "✗" COLOR_RESET " %s: got unexpected value %ld (line %d)\n", \
                   message, (long)(actual), __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_NULL(ptr, message) \
    do { \
        tests_run++; \
        if ((ptr) == NULL) { \
            tests_passed++; \
            printf(COLOR_GREEN "✓" COLOR_RESET " %s\n", message); \
        } else { \
            tests_failed++; \
            printf(COLOR_RED "✗" COLOR_RESET " %s: expected NULL, got %p (line %d)\n", \
                   message, (void*)(ptr), __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_NOT_NULL(ptr, message) \
    do { \
        tests_run++; \
        if ((ptr) != NULL) { \
            tests_passed++; \
            printf(COLOR_GREEN "✓" COLOR_RESET " %s\n", message); \
        } else { \
            tests_failed++; \
            printf(COLOR_RED "✗" COLOR_RESET " %s: expected non-NULL pointer (line %d)\n", \
                   message, __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_STR_EQ(actual, expected, message) \
    do { \
        tests_run++; \
        if (strcmp((actual), (expected)) == 0) { \
            tests_passed++; \
            printf(COLOR_GREEN "✓" COLOR_RESET " %s\n", message); \
        } else { \
            tests_failed++; \
            printf(COLOR_RED "✗" COLOR_RESET " %s: expected \"%s\", got \"%s\" (line %d)\n", \
                   message, (expected), (actual), __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_MEM_EQ(actual, expected, size, message) \
    do { \
        tests_run++; \
        if (memcmp((actual), (expected), (size)) == 0) { \
            tests_passed++; \
            printf(COLOR_GREEN "✓" COLOR_RESET " %s\n", message); \
        } else { \
            tests_failed++; \
            printf(COLOR_RED "✗" COLOR_RESET " %s: memory comparison failed (line %d)\n", \
                   message, __LINE__); \
        } \
    } while(0)

/* Test suite macros */
#define TEST_SUITE_START(name) \
    printf(COLOR_BLUE "Running test suite: %s" COLOR_RESET "\n", name); \
    tests_run = 0; \
    tests_passed = 0; \
    tests_failed = 0;

#define TEST_SUITE_END() \
    printf("\n" COLOR_BLUE "Test Results:" COLOR_RESET "\n"); \
    printf("  Total:  %d\n", tests_run); \
    printf("  " COLOR_GREEN "Passed: %d" COLOR_RESET "\n", tests_passed); \
    if (tests_failed > 0) { \
        printf("  " COLOR_RED "Failed: %d" COLOR_RESET "\n", tests_failed); \
    } else { \
        printf("  Failed: 0\n"); \
    } \
    printf("  Success rate: %.1f%%\n", \
           tests_run > 0 ? (100.0 * tests_passed / tests_run) : 0.0); \
    return tests_failed;

#define RUN_TEST(test_func) \
    do { \
        printf("\n" COLOR_YELLOW "--- %s ---" COLOR_RESET "\n", #test_func); \
        test_func(); \
    } while(0)

/* Utility functions */
static inline void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

static inline uint32_t htonl_test(uint32_t hostlong) {
    return ((hostlong & 0xFF) << 24) |
           (((hostlong >> 8) & 0xFF) << 16) |
           (((hostlong >> 16) & 0xFF) << 8) |
           ((hostlong >> 24) & 0xFF);
}

static inline uint16_t htons_test(uint16_t hostshort) {
    return ((hostshort & 0xFF) << 8) | ((hostshort >> 8) & 0xFF);
}

#endif /* TEST_FRAMEWORK_H */