#include "core/config.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace madoka;

void test_parse_port_list_special_keywords() {
    std::vector<uint16_t> ports;
    bool share_all = false;

    assert(parse_port_list("all", ports, share_all));
    assert(share_all == true);
    assert(ports.empty());

    assert(parse_port_list("*", ports, share_all));
    assert(share_all == true);
    assert(ports.empty());

    assert(parse_port_list("none", ports, share_all));
    assert(share_all == false);
    assert(ports.empty());
}

void test_parse_port_list_individual_ports() {
    std::vector<uint16_t> ports;
    bool share_all = true;

    assert(parse_port_list("80", ports, share_all));
    assert(share_all == false);
    assert(ports.size() == 1);
    assert(ports[0] == 80);

    assert(parse_port_list("80, 443, 8080", ports, share_all));
    assert(share_all == false);
    assert(ports.size() == 3);
    assert(ports[0] == 80);
    assert(ports[1] == 443);
    assert(ports[2] == 8080);

    assert(parse_port_list("8080, 22, 80, 22, 8080", ports, share_all));
    assert(ports.size() == 3);
    assert(ports[0] == 22);
    assert(ports[1] == 80);
    assert(ports[2] == 8080);
}

void test_parse_port_list_ranges() {
    std::vector<uint16_t> ports;
    bool share_all = true;

    assert(parse_port_list("8000-8003", ports, share_all));
    assert(share_all == false);
    assert(ports.size() == 4);
    assert(ports[0] == 8000);
    assert(ports[1] == 8001);
    assert(ports[2] == 8002);
    assert(ports[3] == 8003);

    assert(parse_port_list("22, 8000-8002, 443", ports, share_all));
    assert(share_all == false);
    assert(ports.size() == 5);
    assert(ports[0] == 22);
    assert(ports[1] == 443);
    assert(ports[2] == 8000);
    assert(ports[3] == 8001);
    assert(ports[4] == 8002);
}

void test_parse_port_list_invalid() {
    std::vector<uint16_t> ports;
    bool share_all = false;

    assert(!parse_port_list("", ports, share_all));
    assert(!parse_port_list("   ", ports, share_all));
    assert(!parse_port_list("abc", ports, share_all));
    assert(!parse_port_list("0", ports, share_all));
    assert(!parse_port_list("65536", ports, share_all));
    assert(!parse_port_list("8000-7999", ports, share_all));
    assert(!parse_port_list("8000-", ports, share_all));
    assert(!parse_port_list("-8000", ports, share_all));
    assert(!parse_port_list("80, , 443", ports, share_all));
}

void test_is_port_shared() {
    Config cfg;
    cfg.share_all_ports = true;
    assert(is_port_shared(cfg, 22));
    assert(is_port_shared(cfg, 80));
    assert(is_port_shared(cfg, 65535));

    cfg.share_all_ports = false;
    cfg.shared_ports = {80, 443};
    assert(is_port_shared(cfg, 80));
    assert(is_port_shared(cfg, 443));
    assert(!is_port_shared(cfg, 22));
    assert(!is_port_shared(cfg, 8080));

    cfg.shared_ports.clear();
    assert(!is_port_shared(cfg, 80));
    assert(!is_port_shared(cfg, 443));
}

void test_load_config_with_shared_ports() {
    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto id_path = tmp_dir / "madoka_test_id.key";
    const auto cfg_path = tmp_dir / "madoka_test_ports.conf";

    {
        std::ofstream id_file(id_path);
        id_file << "0123456789abcdef0123456789abcdef0123456789abcdef0123456789a"
                   "bcdef\n";
    }

    {
        std::ofstream cfg_file(cfg_path);
        cfg_file << "network = fd00:1::/64\n"
                 << "identity = " << id_path.filename().string() << "\n"
                 << "shared_ports = 80, 443, 8080-8082\n";
    }

    Config cfg = load_config(cfg_path);
    assert(cfg.share_all_ports == false);
    assert(cfg.shared_ports.size() == 5);
    assert(is_port_shared(cfg, 80));
    assert(is_port_shared(cfg, 443));
    assert(is_port_shared(cfg, 8080));
    assert(is_port_shared(cfg, 8081));
    assert(is_port_shared(cfg, 8082));
    assert(!is_port_shared(cfg, 22));

    std::error_code ec;
    std::filesystem::remove(id_path, ec);
    std::filesystem::remove(cfg_path, ec);
}

void test_default_state_directory() {
    auto state_dir = default_state_directory();
    assert(!state_dir.empty());
    std::string filename = state_dir.filename().string();
    assert(filename == "madoka" || filename == ".madoka");
}

int main() {
    test_parse_port_list_special_keywords();
    test_parse_port_list_individual_ports();
    test_parse_port_list_ranges();
    test_parse_port_list_invalid();
    test_is_port_shared();
    test_load_config_with_shared_ports();
    test_default_state_directory();
    std::cout << "All test_config assertions passed.\n";
    return 0;
}
