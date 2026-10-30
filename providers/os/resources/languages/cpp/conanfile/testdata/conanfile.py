from conan import ConanFile


class AppConan(ConanFile):
    name = "app"
    version = "1.0"
    settings = "os", "compiler", "build_type", "arch"

    requires = "zlib/1.3.1", "fmt/10.2.1"
    tool_requires = ["cmake/3.28.1"]
    python_requires = "conan-tools/1.0.0"

    def requirements(self):
        # Computed at install time — deliberately NOT read.
        if self.options.with_ssl:
            self.requires("openssl/3.2.1")
        self.requires(f"boost/{self.options.boost_version}")
