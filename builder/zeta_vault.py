from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from zeta_forge.cmake_builder import (
    CMakeProjectBuilder,
    CommonBuildArgs,
    cmake_bool,
    common_build_argument_parser,
)
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
            self.repo_config.install_prefix
            / "lib"
            / "cmake"
            / "zeta_deps"
            / self.args.build_type
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
                "$ZETAX_ROOT/zeta_forge/zbuild.py deps --BUILD_TYPE="
                f"{self.args.build_type} --install"
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
            (
                "-DZETA_VAULT_BUILD_TESTS="
                f"{cmake_bool(self.typed_args.build_tests)}"
            ),
            (
                "-DZETA_VAULT_BUILD_EXAMPLES="
                f"{cmake_bool(self.typed_args.build_examples)}"
            ),
        ]


def build_parser() -> argparse.ArgumentParser:
    """Create the zeta_vault build argument parser."""

    parser = common_build_argument_parser("Build zeta_vault")
    parser.add_argument("--no-tests", action="store_true")
    parser.add_argument("--no-examples", action="store_true")
    return parser


def parse_args(argv: list[str] | None = None) -> ZetaVaultBuildArgs:
    """Parse project-specific build arguments."""

    namespace = build_parser().parse_args(argv)
    return ZetaVaultBuildArgs(
        build_type=namespace.build_type,
        install=namespace.install,
        rebuild=namespace.rebuild,
        build_tests=not namespace.no_tests,
        build_examples=not namespace.no_examples,
    )


def project_source_defaults(source_dir_default: Path | None) -> dict[str, Path]:
    """Return optional source defaults supplied by the launcher."""

    defaults: dict[str, Path] = {}
    if source_dir_default is not None:
        defaults["ZETA_VAULT_SRC_DIR"] = source_dir_default
    return defaults


def main(
    script_path: Path,
    *,
    argv: list[str] | None = None,
    source_dir_default: Path | None = None,
) -> int:
    """Run the zeta_vault build workflow."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo_config = load_repo_config(
        script_path,
        project_source_defaults=project_source_defaults(source_dir_default),
    )
    ZetaVaultBuilder(
        script_path=script_path,
        repo_config=repo_config,
        args=args,
    ).run()
    return 0


def cli(script_path: Path, *, source_dir_default: Path | None = None) -> int:
    """Run the CLI and convert failures into a stable nonzero exit code."""

    try:
        return main(script_path, source_dir_default=source_dir_default)
    except Exception as error:
        print(error, file=sys.stderr)
        return 1
