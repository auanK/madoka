#ifndef MADOKA_CRYPTO_IDENTITY_HPP
#define MADOKA_CRYPTO_IDENTITY_HPP

#include "core/config.hpp"
#include "platform/file_lock.hpp"

#include <cstdint>
#include <filesystem>
#include <string>

namespace madoka {

struct Identity {
    void* key{nullptr};

    NodeId id{};

    uint64_t generation{1};

    std::filesystem::path storage_path{};

    std::intptr_t lock_handle{platform::invalid_file_lock};
};

bool identity_load(Identity* identity,
                   const Config& config,
                   std::string* error = nullptr);

void identity_close(Identity* identity);

bool identity_generate(Identity* identity, std::string* error = nullptr);

bool identity_save(Identity* identity,
                   const std::filesystem::path& path,
                   std::string* error = nullptr);

bool identity_bump_generation(Identity* identity, std::string* error = nullptr);

NodeId identity_derive_id(void* evp_pkey);

} // namespace madoka

#endif
