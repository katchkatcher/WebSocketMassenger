#include <gtest/gtest.h>
#include "server/config.h"
#include <fstream>
#include <cstdlib>

TEST(Config, EnvOverridesCliAndJson) {
    std::ofstream jf("test_server.json");
    jf << R"({"address":"10.0.0.1","port":9000,"rate_limit_window_ms":250})";
    jf.close();

    const char* argv[] = {
        "unit_tests",
        "--config", "test_server.json",
        "--port", "7777",
        "--address", "0.0.0.0"
    };
    int argc = 7;


    setenv("WSM_ADDRESS", "9.9.9.9", 1);
    setenv("WSM_PORT", "5555", 1);
    setenv("WSM_RATE_LIMIT_WINDOW_MS", "100", 1);

    Config c;
    c.load(argc, (char**)argv);
    c.validate();

    EXPECT_EQ(c.address, "9.9.9.9");
    EXPECT_EQ(c.port, 5555);
    EXPECT_EQ(c.rate_limit_window.count(), 100);

    unsetenv("WSM_ADDRESS");
    unsetenv("WSM_PORT");
    unsetenv("WSM_RATE_LIMIT_WINDOW_MS");
}