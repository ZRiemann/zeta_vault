from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from zeta_forge.build_cli import Product, Project, Request
from zeta_forge.cmake_builder import (
    CMakeProjectBuilder,
    CommonBuildArgs,
    cmake_bool,
)
from zeta_forge.cmake_engine import CMAKE_ACTIONS, CMakeEngine
from zeta_forge.config import load_repo_config


@dataclass(frozen=True)
class ZetaVaultBuildArgs(CommonBuildArgs):
    """Typed command-line arguments for a zeta_vault build."""

    build_tests: bool
    build_examples: bool


class ZetaVaultBuilder(CMakeProjectBuilder):
    """Build zeta_vault through the shared zeta_forge CMake workflow."""

    source_watch_patterns = (
        "CMakeLists.txt",
        "*.cmake",
        "*.cmake.in",
        "VERSION",
    )
    source_prune_dirs = ("build", "build_debug", "build_err")
    uses_conan = False

    @property
    def project_name(self) -> str:
        """Return the canonical project name."""

        return "zeta_vault"

    @property
    def typed_args(self) -> ZetaVaultBuildArgs:
        """Return the project-specific argument type."""

        return self.args  # type: ignore[return-value]

    @property
    def source_dir(self) -> Path:
        """Return the configured zeta_vault checkout."""

        return self.repo_config.source_dir("ZETA_VAULT_SRC_DIR")

    @property
    def cmake_util_dir(self) -> Path:
        """Return the shared zeta_forge CMake utility directory."""

        return self.repo_config.forge_root / "cmake_util"

    @property
    def zeta_deps_cmake_dir(self) -> Path:
        """Return the installed shared-dependency package directory."""

        return (
            self.repo_config.install_prefix / "lib" / "cmake" / "zeta_deps" / self.args.build_type
        )

    @property
    def missing_source_hint(self) -> str:
        """Return guidance for resolving a missing source checkout."""

        return (
            "Set ZETA_VAULT_SRC_DIR to a local checkout or run from the "
            "zeta_vault checkout with ./zbuild.py"
        )

    def validate(self) -> None:
        """Validate the shared ZetaX build environment."""

        super().validate()
        if not (self.cmake_util_dir / "common.cmake").is_file():
            raise RuntimeError(
                f"zeta_forge cmake_util not found: {self.cmake_util_dir}\n"
                "Ensure $ZETAX_ROOT/zeta_forge/cmake_util exists before "
                "building zeta_vault."
            )
        if not self.zeta_deps_cmake_dir.is_dir():
            raise RuntimeError(
                "ZetaX dependency package configs not found: "
                f"{self.zeta_deps_cmake_dir}\n"
                "Install the shared dependency environment first with: "
                "$ZETAX_ROOT/zeta_forge/zbuild.py install deps --profile "
                f"{self.args.build_type.lower()}"
            )

        candidates = (
            self.zeta_deps_cmake_dir / "libsodium-config.cmake",
            self.repo_config.install_prefix / "lib/cmake/sodium/sodiumConfig.cmake",
            self.repo_config.install_prefix
            / "lib/cmake/unofficial-sodium/unofficial-sodium-config.cmake",
        )
        if not any(path.is_file() for path in candidates):
            raise RuntimeError(
                f"libsodium package configuration is missing for {self.args.build_type}; "
                f"prepare Forge install deps --profile {self.args.build_type.lower()} separately"
            )

    def configure_dependencies(self) -> list[Path]:
        """Return files that invalidate the generated CMake configuration."""

        return [
            self.script_path,
            Path(__file__),
            self.source_dir / "VERSION",
            self.source_dir / "CMakeLists.txt",
        ]

    def conan_install_command(self) -> list[object]:
        """Reject project-local Conan dependency installation."""

        raise RuntimeError("zeta_vault does not use project-local Conan")

    def configure_command(self) -> list[object]:
        """Create the canonical zeta_vault CMake configure command."""

        cmake_prefix_paths = [
            str(self.zeta_deps_cmake_dir),
            str(self.repo_config.install_prefix),
        ]
        return [
            "cmake",
            "-S",
            self.source_dir,
            "-B",
            self.build_dir,
            "-G",
            "Ninja",
            "-Wno-dev",
            f"-DCMAKE_BUILD_TYPE={self.args.build_type}",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            f"-DCMAKE_PREFIX_PATH={';'.join(cmake_prefix_paths)}",
            f"-DCMAKE_INSTALL_PREFIX={self.repo_config.install_prefix}",
            f"-DCMAKE_CXX_STANDARD={self.repo_config.cxx_standard}",
            f"-DZETA_CMAKE_UTIL_DIR={self.cmake_util_dir}",
            f"-DZETA_DEPS_CMAKE_DIR={self.zeta_deps_cmake_dir}",
            (f"-DZETA_VAULT_BUILD_TESTS={cmake_bool(self.typed_args.build_tests)}"),
            (f"-DZETA_VAULT_BUILD_EXAMPLES={cmake_bool(self.typed_args.build_examples)}"),
        ]


def project(script_path: Path) -> Project:
    root = script_path.resolve().parent
    config = load_repo_config(script_path, project_source_defaults={"ZETA_VAULT_SRC_DIR": root})
    defaults = ("zeta_vault_c", "zeta_vault_cpp", "zeta_vault_server", "zeta_vault_ctl")
    names = (*defaults, "zeta_vault_c_example")

    def factory(request: Request, selected: tuple[str, ...]) -> ZetaVaultBuilder:
        args = ZetaVaultBuildArgs(
            request.cmake_profile,
            build_tests=request.action == "test",
            build_examples="zeta_vault_c_example" in selected,
        )
        return ZetaVaultBuilder(script_path=script_path, repo_config=config, args=args)

    def native(selected: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys("zeta_vault_c" if name == "zeta_vault_cpp" else name for name in selected)
        )

    components = {
        "zeta_vault_c": ("zeta_vault_c",),
        "zeta_vault_cpp": ("zeta_vault_c", "zeta_vault_cpp"),
        "zeta_vault_server": ("zeta_vault_server",),
        "zeta_vault_ctl": ("zeta_vault_c", "zeta_vault_ctl"),
    }
    engine = CMakeEngine(
        root,
        factory,
        names,
        native_targets=native,
        components=components,
        test_targets=lambda _: ("zeta_vault_unit_tests", "zeta_vault_integration_tests"),
    )
    products = tuple(
        Product(
            name,
            "cmake",
            "Vault deliverable",
            (
                *CMAKE_ACTIONS,
                *(("install",) if name in defaults else ()),
                *(("run", "dev") if name not in defaults[:2] else ()),
            ),
        )
        for name in names
    )
    return Project("zeta_vault", products, {"cmake": engine}, defaults)
