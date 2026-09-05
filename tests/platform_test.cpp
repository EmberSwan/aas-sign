#include "platform.hpp"

#include <cstdlib>
#include <filesystem>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {
void require(bool condition, const std::string &message)
{
    if (!condition) throw std::runtime_error(message);
}

template<class F> void rejects(F &&operation, const std::string &message)
{
    try { operation(); }
    catch (const std::exception &) { return; }
    throw std::runtime_error(message);
}

void write(const std::string &path, const std::string &bytes)
{
    platform::write_whole_file(path,
        reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size());
}

std::string read(const std::string &path)
{
    platform::File file(path);
    std::string bytes(size_t(file.size()), '\0');
    file.read_at(0, bytes.data(), bytes.size());
    return bytes;
}

std::string encoded(const std::vector<std::string> &args)
{
    std::string result;
    for (const auto &arg : args)
        result += std::to_string(arg.size()) + ":" + arg + "\n";
    return result;
}

std::filesystem::path path_of(const std::string &path)
{
    return std::filesystem::path(std::u8string(path.begin(), path.end()));
}

const std::vector<std::string> secret_names{
    "AZURE_ACCESS_TOKEN", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "AZURE_CLIENT_ID", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
    "GH_TOKEN", "GITHUB_TOKEN", "INPUT_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"
};

void set_environment(const std::string &name, const char *value)
{
#ifdef _WIN32
    if (_putenv_s(name.c_str(), value ? value : "") != 0)
        throw std::runtime_error("set test environment");
#else
    if ((value ? ::setenv(name.c_str(), value, 1) : ::unsetenv(name.c_str())) != 0)
        throw std::runtime_error("set test environment");
#endif
}

struct EnvironmentGuard {
    std::string name, original;
    bool existed;
    explicit EnvironmentGuard(const std::string &key) : name(key), existed(std::getenv(key.c_str()) != nullptr) {
        if (existed) original = std::getenv(key.c_str());
        set_environment(name, "platform-test-sentinel");
    }
    ~EnvironmentGuard() { set_environment(name, existed ? original.c_str() : nullptr); }
};
}  // namespace

int aas_sign_main(int argc, char **argv)
{
    if (argc > 1 && std::string(argv[1]) == "--echo") {
        std::vector<std::string> args;
        for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);
        platform::write_stdout(encoded(args));
        platform::write_stderr("stderr\n");
        return 17;
    }
    if (argc > 1 && std::string(argv[1]) == "--large") {
        platform::write_stdout(std::string(2 * 1024 * 1024 + 19, 'x'));
        return 23;
    }
    if (argc > 1 && std::string(argv[1]) == "--environment") {
        for (const auto &name : secret_names)
            if (std::getenv(name.c_str())) return 91;
        auto visible = std::getenv("AAS_SIGN_PLATFORM_TEST_VISIBLE");
        return visible && std::string(visible) == "platform-test-sentinel" ? 0 : 92;
    }
    if (argc > 2 && std::string(argv[1]) == "--descriptor") {
#ifdef _WIN32
        HANDLE handle = reinterpret_cast<HANDLE>(uintptr_t(std::stoull(argv[2])));
        DWORD flags = 0;
        return GetHandleInformation(handle, &flags) ? 93 : 0;
#else
        int fd = std::stoi(argv[2]);
        return ::fcntl(fd, F_GETFD) < 0 && errno == EBADF ? 0 : 93;
#endif
    }
    try {
        auto self = platform::executable_path();
        require(path_of(self).is_absolute(), "executable_path is absolute");
        require(platform::find_executable(self) == self, "explicit executable resolution");
        std::vector<std::string> args{
            "", "plain", "two words", "'single'", "\"double\"", "ends\\",
            "has\\\"quote", "two\\\\\"quotes", "$HOME; $(echo unsafe) `false` & | < >",
            "line one\nline two", "caf\xc3\xa9-\xe6\x96\x87\xe4\xbb\xb6"
        };
        auto command = args;
        command.insert(command.begin(), "--echo");
        auto result = platform::run_process(self, command);
        require(result.exit_code == 17, "child exit status");
        require(result.output == encoded(args) + "stderr\n", "exact arguments and merged UTF-8 output");
        result = platform::run_process(self, {"--large"});
        require(result.exit_code == 23 && result.output == std::string(1024 * 1024, 'x'),
                "large output is bounded and drained without deadlock");
        rejects([&] { platform::run_process(self, {std::string("a\0b", 3)}); },
                "embedded NUL argument accepted");
        rejects([&] { platform::run_process("aas-sign-missing-platform-test-executable", {}); },
                "missing executable accepted");
        {
            // Keep originals out of child output and restore parent env.
            std::vector<std::unique_ptr<EnvironmentGuard>> environment;
            for (const auto &name : secret_names)
                environment.push_back(std::make_unique<EnvironmentGuard>(name));
            EnvironmentGuard visible("AAS_SIGN_PLATFORM_TEST_VISIBLE");
            require(platform::run_process(self, {"--environment"}).exit_code == 0,
                    "child inherited a signing secret or lost ordinary environment");
        }
#ifdef _WIN32
        {
            SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
            HANDLE sentinel = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                            &attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            require(sentinel != INVALID_HANDLE_VALUE, "create inherited sentinel handle");
            auto child = platform::run_process(self, {"--descriptor", std::to_string(uintptr_t(sentinel))});
            CloseHandle(sentinel);
            require(child.exit_code == 0, "child inherited unrelated parent handle");
        }
#elif defined(__APPLE__) || defined(__GLIBC__)
        {
            int sentinel = ::open("/dev/null", O_RDONLY); // intentionally lacks CLOEXEC
            require(sentinel >= 0, "create inherited sentinel descriptor");
            auto child = platform::run_process(self, {"--descriptor", std::to_string(sentinel)});
            ::close(sentinel);
            require(child.exit_code == 0, "child inherited unrelated parent descriptor");
        }
#endif
        std::vector<std::future<platform::ProcessResult>> workers;
        for (int i = 0; i < 8; ++i)
            workers.emplace_back(std::async(std::launch::async, [&] {
                return platform::run_process(self, command);
            }));
        for (auto &worker : workers) {
            auto child = worker.get();
            require(child.exit_code == 17 && child.output == encoded(args) + "stderr\n",
                    "concurrent process isolation");
        }

        std::string removed;
        {
            platform::TempDir workspace;
            removed = workspace.path();
            require(path_of(removed).is_absolute(), "temporary directory path is absolute");
            std::string original = removed + "/original caf\xc3\xa9.bin";
            write(original, "original");
#ifndef _WIN32
            auto mode = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                        std::filesystem::perms::owner_exec | std::filesystem::perms::group_read;
            std::filesystem::permissions(path_of(original), mode);
            auto directory_mode = std::filesystem::status(path_of(removed)).permissions();
            require((directory_mode & std::filesystem::perms::all) == std::filesystem::perms::owner_all,
                    "temporary workspace is owner-only");
#endif
            platform::TempDir staging(removed);
            auto staged = staging.path() + "/stage.bin";
            platform::copy_file(original, staged);
            require(read(staged) == "original", "copy contents");
            require(platform::same_file(original, original), "same path identity");
            require(!platform::same_file(original, staged), "copy has distinct identity");
            auto alias = removed + "/alias.bin";
            std::filesystem::create_hard_link(path_of(original), path_of(alias));
            require(platform::same_file(original, alias), "hard link identity");
            require(!platform::same_file(original, removed + "/absent.bin"), "absent file identity");
#ifndef _WIN32
            auto symlink = removed + "/symlink.bin";
            std::filesystem::create_symlink(path_of(original), path_of(symlink));
            require(platform::same_file(original, symlink), "symlink identity");
#endif
#ifndef _WIN32
            require(std::filesystem::status(path_of(staged)).permissions() == mode,
                    "copy preserves executable permission mode");
#endif
            rejects([&] { platform::copy_file(original, staged); }, "copy overwrote an existing destination");
            require(read(staged) == "original", "failed copy preserves existing destination");
            write(staged, "signed");
#ifndef _WIN32
            std::filesystem::permissions(path_of(staged), std::filesystem::perms::owner_all);
#endif
            platform::atomic_replace_file(staged, original);
            require(read(original) == "signed" && !std::filesystem::exists(path_of(staged)),
                    "replacement commits stage");
#ifndef _WIN32
            require(std::filesystem::status(path_of(original)).permissions() == mode,
                    "replacement retains original permission mode");
#endif
            rejects([&] { platform::atomic_replace_file(staged, original); }, "missing stage accepted");
            require(read(original) == "signed", "missing stage leaves original unchanged");
            rejects([&] { platform::atomic_replace_file(staging.path(), original); }, "directory stage accepted");
            require(read(original) == "signed", "invalid stage leaves original unchanged");
            rejects([&] { platform::atomic_replace_file(original, original); }, "self replacement accepted");
            require(read(original) == "signed", "self replacement leaves original unchanged");
        }
        require(!std::filesystem::exists(path_of(removed)), "temporary workspace removed recursively");
        platform::write_stdout("platform tests passed\n");
        return 0;
    } catch (const std::exception &error) {
        platform::write_stderr(std::string("platform test: ") + error.what() + "\n");
        return 1;
    }
}

// win32.cpp supplies the Unicode command-line entry point for this test.
#ifndef _WIN32
int main(int argc, char **argv) { return aas_sign_main(argc, argv); }
#endif
