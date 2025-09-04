#include <gtest/gtest.h>
#include "server/logger.h"
#include <filesystem>

TEST(Logger, CreatesRotatingFile) {
    const char* file = "test.log";
    {
        Logger lg(file, "INFO", 1024 * 10, 2);
        lg.info("hello");
        lg.flush();
    }
    EXPECT_TRUE(std::filesystem::exists(file));
}