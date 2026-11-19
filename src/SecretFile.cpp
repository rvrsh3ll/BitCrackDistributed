#include "SecretFile.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <regex>
#include <system_error>
#include <vector>

#include "Logger.h"

#if !defined(_WIN32)
#define SECRET_FILE_POSIX 1
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
// Windows: owner-only protection via a protected DACL (current user +
// SYSTEM + Administrators, no inheritance) - the faithful equivalent of the
// POSIX 0600 (where root can still read). New files are created with the
// DACL already set; existing files are narrowed BEFORE any secret content is
// (re)written, and the DACL is protected so directory grants cannot flow
// back in.
#include <windows.h>
#include <aclapi.h>
#endif

namespace fs = std::filesystem;

#ifndef SECRET_FILE_POSIX
namespace {

// Builds an ACL granting FILE_ALL_ACCESS to the current user, SYSTEM and
// Administrators only. The ACL lives in `acl_buf` (caller-owned).
bool buildOwnerOnlyAcl(PACL* out_acl, std::vector<unsigned char>& acl_buf) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<unsigned char> user_buf(len ? len : 128);
    if (len == 0 || !GetTokenInformation(token, TokenUser, user_buf.data(), len, &len)) {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);
    const PSID user_sid = reinterpret_cast<TOKEN_USER*>(user_buf.data())->User.Sid;

    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID sid_system = nullptr;
    PSID sid_admins = nullptr;
    if (!AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sid_system)) return false;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &sid_admins)) {
        FreeSid(sid_system);
        return false;
    }

    const PSID sids[3] = {user_sid, sid_system, sid_admins};
    DWORD acl_size = sizeof(ACL);
    for (PSID s : sids) acl_size += sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(s) - sizeof(DWORD);
    acl_buf.assign(acl_size, 0);
    PACL acl = reinterpret_cast<PACL>(acl_buf.data());
    bool ok = InitializeAcl(acl, acl_size, ACL_REVISION) != FALSE;
    for (size_t i = 0; ok && i < 3; ++i) ok = AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sids[i]) != FALSE;
    FreeSid(sid_system);
    FreeSid(sid_admins);
    if (!ok) return false;
    *out_acl = acl;
    return true;
}

// Applies the owner-only DACL to `wpath`, cutting off inheritance.
bool applyOwnerOnlyAcl(const wchar_t* wpath) {
    std::vector<unsigned char> acl_buf;
    PACL acl = nullptr;
    if (!buildOwnerOnlyAcl(&acl, acl_buf)) return false;
    const DWORD r = SetNamedSecurityInfoW(const_cast<LPWSTR>(wpath), SE_FILE_OBJECT,
                                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                          nullptr, nullptr, acl, nullptr);
    return r == ERROR_SUCCESS;
}

// SECURITY_DESCRIPTOR wrapper so CreateFileW births new files narrowed.
struct OwnerOnlySd {
    std::vector<unsigned char> acl_buf;
    SECURITY_DESCRIPTOR sd {};
    bool ok = false;
    OwnerOnlySd() {
        PACL acl = nullptr;
        if (!buildOwnerOnlyAcl(&acl, acl_buf)) return;
        if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) return;
        if (!SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE)) return;
        ok = true;
    }
};

bool writeFileWin(const std::string& path, const std::string& text, bool append) {
    const fs::path p(path);
    std::error_code ec;
    // An existing file keeps its old DACL when opened: narrow it first so the
    // secret is never briefly readable by others.
    if (fs::exists(p, ec)) (void)applyOwnerOnlyAcl(p.c_str());
    OwnerOnlySd osd;
    SECURITY_ATTRIBUTES sa {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    if (osd.ok) sa.lpSecurityDescriptor = &osd.sd;
    const DWORD access = append ? FILE_APPEND_DATA : static_cast<DWORD>(GENERIC_WRITE);
    const DWORD creation = append ? OPEN_ALWAYS : CREATE_ALWAYS;
    HANDLE h = CreateFileW(p.c_str(), access, FILE_SHARE_READ, &sa, creation, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    if (osd.ok) (void)applyOwnerOnlyAcl(p.c_str());  // belt and braces for the fresh-file case
    bool ok = true;
    size_t off = 0;
    while (off < text.size()) {
        DWORD written = 0;
        const DWORD want = static_cast<DWORD>(std::min<size_t>(text.size() - off, 0x40000000UL));
        if (!WriteFile(h, text.data() + off, want, &written, nullptr) || written == 0) {
            ok = false;
            break;
        }
        off += written;
    }
    FlushFileBuffers(h);
    CloseHandle(h);
    return ok;
}

bool isGroupOrOtherAccessibleWin(const std::string& path) {
    const fs::path p(path);
    std::error_code ec;
    if (!fs::is_regular_file(p, ec)) return false;  // match the POSIX lstat+S_ISREG guard
    PSECURITY_DESCRIPTOR sd = nullptr;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    const DWORD r = GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT,
                                          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                          &owner, nullptr, &dacl, nullptr, &sd);
    if (r != ERROR_SUCCESS) return false;  // cannot inspect: do not claim exposure
    bool exposed = false;
    if (!dacl) {
        exposed = true;  // a NULL DACL grants everyone full access
    } else {
        SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
        PSID sid_system = nullptr;
        PSID sid_admins = nullptr;
        AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sid_system);
        AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &sid_admins);
        ACL_SIZE_INFORMATION info {};
        WORD count = 0;
        if (GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation)) count = info.AceCount;
        for (WORD i = 0; i < count && !exposed; ++i) {
            void* ace = nullptr;
            if (!GetAce(dacl, i, &ace)) continue;
            const auto* hdr = static_cast<ACE_HEADER*>(ace);
            PSID sid = nullptr;
            if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                sid = &static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart;
            } else if (hdr->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE) {
                sid = &static_cast<ACCESS_ALLOWED_CALLBACK_ACE*>(ace)->SidStart;
            } else if (hdr->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
                auto* oa = static_cast<ACCESS_ALLOWED_OBJECT_ACE*>(ace);
                BYTE* b = reinterpret_cast<BYTE*>(&oa->SidStart);
                if (oa->Flags & ACE_OBJECT_TYPE_PRESENT) b += sizeof(GUID);
                if (oa->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) b += sizeof(GUID);
                sid = reinterpret_cast<PSID>(b);
            } else {
                continue;  // deny/audit ACEs grant nothing
            }
            if (owner && EqualSid(sid, owner)) continue;
            if (sid_system && EqualSid(sid, sid_system)) continue;
            if (sid_admins && EqualSid(sid, sid_admins)) continue;
            exposed = true;  // any other principal (e.g. inherited Users/Everyone)
        }
        if (sid_system) FreeSid(sid_system);
        if (sid_admins) FreeSid(sid_admins);
    }
    LocalFree(sd);
    return exposed;
}

}  // namespace
#endif  // !SECRET_FILE_POSIX

namespace secret_file {

bool appendOwnerOnly(const std::string& path, const std::string& text) {
#ifdef SECRET_FILE_POSIX
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    if (::fchmod(fd, 0600) != 0) { ::close(fd); return false; }  // existing file: narrow it first
    size_t off = 0;
    while (off < text.size()) {
        ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        off += static_cast<size_t>(n);
    }
    (void)::fsync(fd);
    return ::close(fd) == 0;
#else
    return writeFileWin(path, text, /*append=*/true);
#endif
}

bool writeOwnerOnly(const std::string& path, const std::string& text) {
#ifdef SECRET_FILE_POSIX
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    // Narrow first, then truncate and write: the content is never readable
    // by group/other, not even briefly.
    if (::fchmod(fd, 0600) != 0 || ::ftruncate(fd, 0) != 0) { ::close(fd); return false; }
    size_t off = 0;
    while (off < text.size()) {
        ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        off += static_cast<size_t>(n);
    }
    (void)::fsync(fd);
    return ::close(fd) == 0;
#else
    return writeFileWin(path, text, /*append=*/false);
#endif
}

bool isGroupOrOtherAccessible(const std::string& path) {
#ifdef SECRET_FILE_POSIX
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    return (st.st_mode & 077) != 0;
#else
    return isGroupOrOtherAccessibleWin(path);
#endif
}

bool restrictToOwner(const std::string& path) {
#ifdef SECRET_FILE_POSIX
    if (!isGroupOrOtherAccessible(path)) return false;
    return ::chmod(path.c_str(), 0600) == 0;
#else
    if (!isGroupOrOtherAccessibleWin(path)) return false;
    return applyOwnerOnlyAcl(fs::path(path).c_str());
#endif
}

std::string foundKeyLogPath(const std::string& dir, uint32_t puzzle_number) {
    char name[64];
    std::snprintf(name, sizeof name, "puzzle%02uFoundKey.log", static_cast<unsigned>(puzzle_number));
    return (fs::path(dir.empty() ? "." : dir) / name).string();
}

bool writeFoundKeyRecord(const std::string& dir, uint32_t puzzle_number, const std::string& solver_address,
                         const std::string& alias, const std::string& private_key, const std::string& status,
                         const std::string& extra) {
    const std::string d = dir.empty() ? "." : dir;
    std::error_code ec;
    fs::create_directories(d, ec);
    const std::string path = foundKeyLogPath(d, puzzle_number);
    const bool ok = appendOwnerOnly(path, "solver=" + solver_address + " alias=" + alias + " key=" + private_key +
                                              " status=" + status + (extra.empty() ? std::string() : " " + extra) +
                                              "\n");
    if (ok) Logger::info("Found key recorded (" + status + ") in " + path + " (owner-only)");
    else Logger::error("Could not write the found key to " + path + "; it is NOT saved anywhere else");
    return ok;
}

std::vector<FoundKeyRecord> readFoundKeyRecords(const std::string& dir) {
    std::vector<FoundKeyRecord> out;
    std::error_code ec;
    const fs::path d(dir.empty() ? "." : dir);
    if (!fs::is_directory(d, ec)) return out;
    static const std::regex name_re("^puzzle([0-9]+)FoundKey\\.log$");
    for (fs::directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        std::smatch m;
        if (!std::regex_match(name, m, name_re)) continue;
        FoundKeyRecord rec;
        try {
            rec.puzzle_number = static_cast<uint32_t>(std::stoul(m[1].str()));
        } catch (...) {
            continue;
        }
        rec.path = it->path().string();
        std::ifstream f(it->path());
        std::string line;
        bool any = false;
        while (std::getline(f, line)) {
            std::map<std::string, std::string> kv;
            size_t pos = 0;
            while (pos < line.size()) {
                size_t sp = line.find(' ', pos);
                if (sp == std::string::npos) sp = line.size();
                const std::string tok = line.substr(pos, sp - pos);
                const size_t eq = tok.find('=');
                if (eq != std::string::npos && eq > 0) kv[tok.substr(0, eq)] = tok.substr(eq + 1);
                pos = sp + 1;
            }
            if (!kv.count("key") || !kv.count("status") || kv["key"].empty()) continue;
            for (auto& e : kv) rec.fields[e.first] = e.second;
            any = true;
        }
        if (any) out.push_back(std::move(rec));
    }
    return out;
}

int tightenFoundKeyFiles(const std::string& dir) {
    int changed = 0;
    std::error_code ec;
    const fs::path d(dir.empty() ? "." : dir);
    if (!fs::is_directory(d, ec)) return 0;
    static const std::regex name_re("^puzzle[0-9]+FoundKey\\.log$");
    for (fs::directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (!std::regex_match(name, name_re)) continue;
        if (restrictToOwner(it->path().string())) {
            ++changed;
            Logger::warn("Found-key file was readable by others; permissions reset to 0600: " + it->path().string());
        }
    }
    return changed;
}

}  // namespace secret_file
