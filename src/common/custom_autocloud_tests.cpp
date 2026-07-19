#include "custom_autocloud.h"
#include <cstdlib>
#include <iostream>

static void Check(bool value, const char* message) {
    if (!value) { std::cerr << message << std::endl; std::exit(1); }
}

int main() {
    std::string error;
    auto good = CustomAutoCloud::ParseConfig(R"({
      "custom_autocloud":{"3751950":{"managed_by":"cargodeck","strategy":"steam-first",
      "rules":[{"root":"GameInstall","path":"saves","pattern":"*.save","recursive":true}]}}
    })", 3751950, &error);
    Check(error.empty() && good.size() == 1, "valid rule rejected");
    Check(good[0].root == "GameInstall" && good[0].pattern == "*.save", "valid rule changed");

    for (const char* bad : {
        R"({"custom_autocloud":{"1":{"strategy":"steam-first","rules":[{"root":"GameInstall","path":"../saves","pattern":"*.save","recursive":true}]}}})",
        R"({"custom_autocloud":{"1":{"strategy":"steam-first","rules":[{"root":"Unknown","path":"saves","pattern":"*.save","recursive":true}]}}})",
        R"({"custom_autocloud":{"1":{"strategy":"steam-first","rules":[{"root":"GameInstall","path":"saves","pattern":"../*.save","recursive":true}]}}})"
    }) {
        error.clear();
        Check(CustomAutoCloud::ParseConfig(bad, 1, &error).empty() && !error.empty(), "unsafe rule accepted");
    }
    return 0;
}
