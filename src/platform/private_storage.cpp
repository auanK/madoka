#include "platform/private_storage.hpp"

#include "platform/durability.hpp"
#include "platform/random.hpp"

#include <array>
#include <fstream>
#include <system_error>
#include <vector>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
// clang-format on
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace madoka::platform {
namespace {

std::string random_hex(std::string* error) {
    std::array<uint8_t, 16> bytes{};
    if (!random_bytes(bytes, error)) {
        return {};
    }
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const uint8_t byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

#ifdef _WIN32
bool apply_private_acl(const std::filesystem::path& path,
                       bool directory,
                       std::string* error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (error != nullptr) {
            *error = "Cannot query current Windows account";
        }
        return false;
    }
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> data(size);
    const bool read =
        size != 0 &&
        GetTokenInformation(token, TokenUser, data.data(), size, &size) != 0;
    CloseHandle(token);
    if (!read) {
        if (error != nullptr) {
            *error = "Cannot read current Windows account";
        }
        return false;
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(data.data());
    LPWSTR sid_text = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid_text)) {
        if (error != nullptr) {
            *error = "Cannot encode current Windows account";
        }
        return false;
    }
    const std::wstring inherit = directory ? L"OICI" : L"";
    const std::wstring sddl = L"D:P(A;" + inherit + L";FA;;;SY)(A;" + inherit +
                              L";FA;;;" + sid_text + L")";
    LocalFree(sid_text);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        if (error != nullptr) {
            *error = "Cannot build private Windows ACL";
        }
        return false;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL acl = nullptr;
    const bool acl_ok = GetSecurityDescriptorDacl(
                            descriptor, &present, &acl, &defaulted) != 0 &&
                        present;
    DWORD result = ERROR_INVALID_SECURITY_DESCR;
    if (acl_ok) {
        auto writable = path.wstring();
        result = SetNamedSecurityInfoW(writable.data(),
                                       SE_FILE_OBJECT,
                                       DACL_SECURITY_INFORMATION |
                                           PROTECTED_DACL_SECURITY_INFORMATION,
                                       nullptr,
                                       nullptr,
                                       acl,
                                       nullptr);
    }
    LocalFree(descriptor);
    if (!acl_ok || result != ERROR_SUCCESS) {
        if (error != nullptr) {
            *error =
                "Cannot apply private Windows ACL: " + std::to_string(result);
        }
        return false;
    }
    return true;
}
#endif

bool reject_link(const std::filesystem::path& path,
                 bool directory,
                 std::string* error) {
    std::error_code code;
    const auto status = std::filesystem::symlink_status(path, code);
    if (code || std::filesystem::is_symlink(status) ||
        (directory && !std::filesystem::is_directory(status)) ||
        (!directory && !std::filesystem::is_regular_file(status))) {
        if (error != nullptr) {
            *error = std::string{directory ? "Invalid private directory: "
                                           : "Invalid private file: "} +
                     path.string();
        }
        return false;
    }
#ifdef _WIN32
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        if (error != nullptr) {
            *error = "Reparse points are not allowed in private storage";
        }
        return false;
    }
    if (!directory) {
        const HANDLE file = CreateFileW(path.c_str(),
                                        FILE_READ_ATTRIBUTES,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr,
                                        OPEN_EXISTING,
                                        FILE_FLAG_OPEN_REPARSE_POINT,
                                        nullptr);
        BY_HANDLE_FILE_INFORMATION info{};
        const bool valid = file != INVALID_HANDLE_VALUE &&
                           GetFileInformationByHandle(file, &info) != 0 &&
                           info.nNumberOfLinks == 1;
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
        }
        if (!valid) {
            if (error != nullptr) {
                *error = "Private files cannot have multiple links";
            }
            return false;
        }
    }
#else
    if (!directory) {
        struct stat info{};
        if (::lstat(path.c_str(), &info) != 0 || info.st_nlink != 1 ||
            info.st_uid != geteuid()) {
            if (error != nullptr) {
                *error = "Private files must be owner-only regular files "
                         "without links";
            }
            return false;
        }
    }
#endif
    return true;
}

bool create_empty_private_file(const std::filesystem::path& path,
                               std::string* error) {
#ifdef _WIN32
    const HANDLE file = CreateFileW(path.c_str(),
                                    GENERIC_READ | GENERIC_WRITE,
                                    0,
                                    nullptr,
                                    CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(file);
    if (!apply_private_acl(path, false, error)) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        return false;
    }
    return true;
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int file = ::open(path.c_str(), flags, 0600);
    if (file < 0) {
        return false;
    }
    if (::close(file) != 0) {
        if (error != nullptr) {
            *error = "Cannot close private temporary file";
        }
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        return false;
    }
    return true;
#endif
}

} // namespace

bool private_ensure_directory(const std::filesystem::path& path,
                              std::string* error) {
    if (path.empty()) {
        if (error != nullptr) {
            *error = "Private directory path is empty";
        }
        return false;
    }
    std::error_code code;
    if (!std::filesystem::exists(path, code)) {
        if (!std::filesystem::create_directory(path, code) || code) {
            if (error != nullptr) {
                *error = "Cannot create private directory: " + code.message();
            }
            return false;
        }
    }
    if (!reject_link(path, true, error)) {
        return false;
    }
#ifdef _WIN32
    return apply_private_acl(path, true, error);
#else
    if (::chmod(path.c_str(), 0700) != 0) {
        if (error != nullptr) {
            *error = "Cannot protect private directory";
        }
        return false;
    }
    return true;
#endif
}

bool private_protect_file(const std::filesystem::path& path,
                          std::string* error) {
    if (!reject_link(path, false, error)) {
        return false;
    }
#ifdef _WIN32
    return apply_private_acl(path, false, error);
#else
    if (::chmod(path.c_str(), 0600) != 0) {
        if (error != nullptr) {
            *error = "Cannot protect private file";
        }
        return false;
    }
    return true;
#endif
}

bool private_write_atomically(const std::filesystem::path& path,
                              std::string_view bytes,
                              std::string* error) {
    if (path.empty() || path.parent_path().empty() ||
        !reject_link(path.parent_path(), true, error)) {
        return false;
    }
    std::error_code target_error;
    if (std::filesystem::exists(path, target_error) &&
        !private_protect_file(path, error)) {
        return false;
    }
    if (target_error) {
        if (error != nullptr) {
            *error = "Cannot inspect private file: " + target_error.message();
        }
        return false;
    }

    for (int attempt = 0; attempt < 16; ++attempt) {
        const std::string suffix = random_hex(error);
        if (suffix.empty()) {
            return false;
        }
        const auto temporary =
            path.parent_path() / (path.filename().string() + ".tmp." + suffix);
        std::error_code exists_error;
        if (!create_empty_private_file(temporary, error)) {
            if (error != nullptr && !error->empty()) {
                return false;
            }
            if (!std::filesystem::exists(temporary, exists_error)) {
                if (exists_error) {
                    if (error != nullptr) {
                        *error = "Cannot inspect private temporary file";
                    }
                    return false;
                }
                if (error != nullptr) {
                    *error = "Cannot create private temporary file";
                }
                return false;
            }
            continue;
        }
        {
            std::ofstream output(
                temporary, std::ios::binary | std::ios::out | std::ios::trunc);
            if (!output ||
                (!bytes.empty() &&
                 !output.write(bytes.data(),
                               static_cast<std::streamsize>(bytes.size()))) ||
                !output.flush()) {
                output.close();
                std::filesystem::remove(temporary, exists_error);
                if (error != nullptr) {
                    *error = "Cannot write private file";
                }
                return false;
            }
        }
        if (!private_protect_file(temporary, error) ||
            !sync_file(temporary, error) ||
            !replace_atomically(temporary, path, error) ||
            !sync_parent_directory(path, error)) {
            std::filesystem::remove(temporary, exists_error);
            return false;
        }
        return true;
    }
    if (error != nullptr) {
        *error = "Cannot reserve a private temporary file";
    }
    return false;
}

bool private_read_file(const std::filesystem::path& path,
                       std::size_t maximum_size,
                       std::string* contents,
                       std::string* error) {
    if (contents == nullptr || !private_protect_file(path, error)) {
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        if (error != nullptr) {
            *error = "Cannot open private file";
        }
        return false;
    }
    std::string result(maximum_size + 1, '\0');
    input.read(result.data(), static_cast<std::streamsize>(result.size()));
    result.resize(static_cast<std::size_t>(input.gcount()));
    if (input.bad() || result.size() > maximum_size) {
        if (error != nullptr) {
            *error = "Private file exceeds its size limit";
        }
        return false;
    }
    *contents = std::move(result);
    return true;
}

} // namespace madoka::platform
