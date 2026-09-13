#include "crypto/identity.hpp"

#include "platform/file_lock.hpp"
#include "platform/private_storage.hpp"

#include <array>
#include <charconv>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <string_view>

namespace madoka {
namespace {

constexpr std::string_view identity_header = "Madoka-Identity: 1\nNode-ID: ";
constexpr std::string_view generation_header = "Generation: ";
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;

bool encode_identity(EVP_PKEY* key,
                     const NodeId& id,
                     uint64_t generation,
                     std::string* output,
                     std::string* error) {
    Bio pem(BIO_new(BIO_s_mem()), BIO_free);
    if (output == nullptr || !pem ||
        PEM_write_bio_PrivateKey(
            pem.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        if (error != nullptr) {
            *error = "Cannot encode Ed25519 identity";
        }
        return false;
    }
    char* data = nullptr;
    const auto length = BIO_get_mem_data(pem.get(), &data);
    if (length <= 0) {
        if (error != nullptr) {
            *error = "Cannot read encoded Ed25519 identity";
        }
        return false;
    }
    *output = std::string{identity_header} + hex(id) + "\n" +
              std::string{generation_header} + std::to_string(generation) +
              "\n" + std::string{data, static_cast<std::size_t>(length)};
    return true;
}

bool decode_identity(std::string_view text,
                     EVP_PKEY** output_key,
                     NodeId* output_id,
                     uint64_t* output_generation,
                     std::string* error) {
    const std::size_t id_offset = identity_header.size();
    const std::size_t id_end = id_offset + 64;
    if (output_key == nullptr || output_id == nullptr ||
        output_generation == nullptr || !text.starts_with(identity_header) ||
        text.size() <= id_end || text[id_end] != '\n') {
        if (error != nullptr) {
            *error = "Invalid identity file; refusing to regenerate it";
        }
        return false;
    }

    NodeId saved_id{};
    try {
        saved_id = parse_node_id(text.substr(id_offset, 64));
    } catch (...) {
        if (error != nullptr) {
            *error = "Invalid identity Node ID";
        }
        return false;
    }

    std::size_t offset = id_end + 1;
    if (!text.substr(offset).starts_with(generation_header)) {
        if (error != nullptr) {
            *error = "Identity generation is missing";
        }
        return false;
    }
    const std::size_t generation_end = text.find('\n', offset);
    const std::size_t generation_offset = offset + generation_header.size();
    uint64_t generation = 0;
    if (generation_end == std::string_view::npos ||
        generation_end == generation_offset) {
        if (error != nullptr) {
            *error = "Invalid identity generation";
        }
        return false;
    }
    const auto [end, parse_error] =
        std::from_chars(text.data() + generation_offset,
                        text.data() + generation_end,
                        generation);
    if (parse_error != std::errc{} || end != text.data() + generation_end ||
        generation == 0) {
        if (error != nullptr) {
            *error = "Invalid identity generation";
        }
        return false;
    }
    offset = generation_end + 1;
    if (!text.substr(offset).starts_with("-----BEGIN PRIVATE KEY-----\n") ||
        !text.ends_with("-----END PRIVATE KEY-----\n")) {
        if (error != nullptr) {
            *error = "Invalid identity private key";
        }
        return false;
    }

    Bio pem(BIO_new_mem_buf(text.data() + offset,
                            static_cast<int>(text.size() - offset)),
            BIO_free);
    EVP_PKEY* key = pem ? PEM_read_bio_PrivateKey(
                              pem.get(),
                              nullptr,
                              [](char*, int, int, void*) {
                                  return 0;
                              },
                              nullptr)
                        : nullptr;
    if (key == nullptr || BIO_ctrl_pending(pem.get()) != 0) {
        EVP_PKEY_free(key);
        if (error != nullptr) {
            *error = "Cannot decode identity private key";
        }
        return false;
    }
    try {
        if (identity_derive_id(key) != saved_id) {
            EVP_PKEY_free(key);
            if (error != nullptr) {
                *error = "Identity checksum does not match its private key";
            }
            return false;
        }
    } catch (const std::exception& exception) {
        EVP_PKEY_free(key);
        if (error != nullptr) {
            *error = exception.what();
        }
        return false;
    }
    *output_key = key;
    *output_id = saved_id;
    *output_generation = generation;
    return true;
}

} // namespace

NodeId identity_derive_id(void* evp_pkey) {
    auto* key = reinterpret_cast<EVP_PKEY*>(evp_pkey);
    std::array<uint8_t, 32> public_key{};
    std::size_t size = public_key.size();
    NodeId id{};
    if (key == nullptr || !EVP_PKEY_is_a(key, "ED25519") ||
        EVP_PKEY_get_raw_public_key(key, public_key.data(), &size) != 1 ||
        size != public_key.size() ||
        EVP_Q_digest(nullptr,
                     "SHA256",
                     nullptr,
                     public_key.data(),
                     public_key.size(),
                     id.data(),
                     &size) != 1 ||
        size != id.size()) {
        throw std::runtime_error("Cannot derive an Ed25519 node identity");
    }
    return id;
}

bool identity_load(Identity* identity,
                   const Config& config,
                   std::string* error) {
    if (identity == nullptr || config.identity_file.empty()) {
        if (error != nullptr) {
            *error = "Invalid identity path";
        }
        return false;
    }
    identity_close(identity);
    auto lock_path = config.identity_file;
    lock_path += ".lock";
    if (!platform::file_lock_acquire(
            lock_path, &identity->lock_handle, error)) {
        return false;
    }

    std::error_code exists_error;
    const bool exists =
        std::filesystem::exists(config.identity_file, exists_error);
    if (exists_error) {
        if (error != nullptr) {
            *error = "Cannot inspect identity file: " + exists_error.message();
        }
        identity_close(identity);
        return false;
    }

    EVP_PKEY* key = nullptr;
    NodeId id{};
    uint64_t generation = 1;
    if (exists) {
        std::string contents;
        if (!platform::private_read_file(
                config.identity_file, 4096, &contents, error) ||
            !decode_identity(contents, &key, &id, &generation, error)) {
            identity_close(identity);
            return false;
        }
    } else {
        key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        if (key == nullptr) {
            if (error != nullptr) {
                *error = "Cannot generate Ed25519 identity";
            }
            identity_close(identity);
            return false;
        }
        try {
            id = identity_derive_id(key);
            validate_identity_address(id);
        } catch (const std::exception& exception) {
            EVP_PKEY_free(key);
            if (error != nullptr) {
                *error = exception.what();
            }
            identity_close(identity);
            return false;
        }
        std::string encoded;
        if (!encode_identity(key, id, generation, &encoded, error) ||
            !platform::private_write_atomically(
                config.identity_file, encoded, error)) {
            EVP_PKEY_free(key);
            identity_close(identity);
            return false;
        }
    }

    try {
        validate_identity_address(id);
    } catch (const std::exception& exception) {
        EVP_PKEY_free(key);
        if (error != nullptr) {
            *error = exception.what();
        }
        identity_close(identity);
        return false;
    }
    identity->key = key;
    identity->id = id;
    identity->generation = generation;
    identity->storage_path = config.identity_file;
    return true;
}

void identity_close(Identity* identity) {
    if (identity == nullptr) {
        return;
    }
    EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(identity->key));
    identity->key = nullptr;
    platform::file_lock_release(&identity->lock_handle);
    identity->id.fill(0);
    identity->generation = 1;
    identity->storage_path.clear();
}

bool identity_generate(Identity* identity, std::string* error) {
    if (identity == nullptr) {
        if (error != nullptr) {
            *error = "Identity pointer is null";
        }
        return false;
    }
    identity_close(identity);
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
    if (key == nullptr) {
        if (error != nullptr) {
            *error = "Cannot generate Ed25519 identity";
        }
        return false;
    }
    try {
        identity->id = identity_derive_id(key);
    } catch (const std::exception& exception) {
        EVP_PKEY_free(key);
        if (error != nullptr) {
            *error = exception.what();
        }
        return false;
    }
    identity->key = key;
    return true;
}

bool identity_save(Identity* identity,
                   const std::filesystem::path& path,
                   std::string* error) {
    if (identity == nullptr || identity->key == nullptr || path.empty()) {
        if (error != nullptr) {
            *error = "Invalid identity to save";
        }
        return false;
    }
    if (identity->lock_handle == platform::invalid_file_lock) {
        auto lock_path = path;
        lock_path += ".lock";
        if (!platform::file_lock_acquire(
                lock_path, &identity->lock_handle, error)) {
            return false;
        }
    }
    std::string encoded;
    if (!encode_identity(reinterpret_cast<EVP_PKEY*>(identity->key),
                         identity->id,
                         identity->generation,
                         &encoded,
                         error) ||
        !platform::private_write_atomically(path, encoded, error)) {
        return false;
    }
    identity->storage_path = path;
    return true;
}

bool identity_bump_generation(Identity* identity, std::string* error) {
    if (identity == nullptr || identity->key == nullptr ||
        identity->generation == UINT64_MAX) {
        if (error != nullptr) {
            *error = "Identity generation cannot be advanced";
        }
        return false;
    }
    const uint64_t generation = identity->generation + 1;
    if (!identity->storage_path.empty()) {
        std::string encoded;
        if (!encode_identity(reinterpret_cast<EVP_PKEY*>(identity->key),
                             identity->id,
                             generation,
                             &encoded,
                             error) ||
            !platform::private_write_atomically(
                identity->storage_path, encoded, error)) {
            return false;
        }
    }
    identity->generation = generation;
    return true;
}

} // namespace madoka
