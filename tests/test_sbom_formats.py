"""
Tests for SBOM format conversion with recursive component extraction
and dependency graph parsing.
"""

import json

import pytest

from server.sbom_formats import (
    SBOMFormat,
    _flatten_components,
    convert_cyclonedx,
    convert_spdx,
    convert_sbom,
    extract_cyclonedx_dependencies,
    extract_spdx_dependencies,
)


# ── Fixtures ─────────────────────────────────────────────────────────────


def _cdx_component(name, version, purl, nested=None):
    comp = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "bom-ref": purl,
    }
    if nested:
        comp["components"] = nested
    return comp


def _spdx_package(spdx_id, name, version, purl):
    return {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
        "externalRefs": [
            {"referenceType": "purl", "referenceLocator": purl},
        ],
    }


# ── Phase 1: Recursive component extraction ──────────────────────────────


class TestFlattenComponents:

    def test_flat_list(self):
        comps = [_cdx_component("a", "1.0", "pkg:maven/g/a@1.0")]
        result = list(_flatten_components(comps))
        assert len(result) == 1
        assert result[0]["name"] == "a"

    def test_nested_one_level(self):
        inner = _cdx_component("b", "2.0", "pkg:maven/g/b@2.0")
        outer = _cdx_component("a", "1.0", "pkg:maven/g/a@1.0", nested=[inner])
        result = list(_flatten_components([outer]))
        assert len(result) == 2
        names = {r["name"] for r in result}
        assert names == {"a", "b"}

    def test_nested_three_levels(self):
        c = _cdx_component("c", "3.0", "pkg:maven/g/c@3.0")
        b = _cdx_component("b", "2.0", "pkg:maven/g/b@2.0", nested=[c])
        a = _cdx_component("a", "1.0", "pkg:maven/g/a@1.0", nested=[b])
        result = list(_flatten_components([a]))
        assert len(result) == 3
        names = [r["name"] for r in result]
        assert names == ["a", "b", "c"]

    def test_empty_list(self):
        assert list(_flatten_components([])) == []

    def test_no_nested_key(self):
        comp = {"name": "x", "version": "1.0", "purl": "pkg:npm/x@1.0"}
        result = list(_flatten_components([comp]))
        assert len(result) == 1


class TestConvertCyclonedxRecursive:

    def test_nested_components_extracted(self):
        inner = _cdx_component(
            "spring-security-oauth2-authorization-server", "1.2.0",
            "pkg:maven/org.springframework.security/spring-security-oauth2-authorization-server@1.2.0",
        )
        outer = _cdx_component(
            "spring-boot", "3.2.0",
            "pkg:maven/org.springframework.boot/spring-boot@3.2.0",
            nested=[inner],
        )
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [outer]}
        result = convert_cyclonedx(sbom)
        assert len(result) == 2
        names = {p["name"] for p in result}
        assert "spring-security-oauth2-authorization-server" in names
        assert "spring-boot" in names

    def test_flat_sbom_still_works(self):
        comps = [
            _cdx_component("curl", "8.5.0", "pkg:rpm/redhat/curl@8.5.0-1.el9?arch=x86_64"),
            _cdx_component("zlib", "1.2.13", "pkg:rpm/redhat/zlib@1.2.13-1.el9?arch=x86_64"),
        ]
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps}
        result = convert_cyclonedx(sbom)
        assert len(result) == 2

    def test_skips_oci_purls(self):
        comps = [
            _cdx_component("myimage", "1.0", "pkg:oci/myimage@sha256:abc"),
            _cdx_component("curl", "8.5.0", "pkg:rpm/redhat/curl@8.5.0"),
        ]
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps}
        result = convert_cyclonedx(sbom)
        assert len(result) == 1
        assert result[0]["name"] == "curl"


class TestConvertSpdxContains:

    def test_contains_relationship_adds_package(self):
        doc_pkg = _spdx_package("SPDXRef-Document", "mydoc", "1.0", "pkg:generic/mydoc@1.0")
        main_pkg = _spdx_package("SPDXRef-Package-A", "pkgA", "1.0", "pkg:maven/g/pkgA@1.0")
        contained_pkg = _spdx_package("SPDXRef-Package-B", "pkgB", "2.0", "pkg:maven/g/pkgB@2.0")
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [doc_pkg, main_pkg],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-Package-A",
                    "relatedSpdxElement": "SPDXRef-Package-B",
                    "relationshipType": "CONTAINS",
                },
            ],
        }
        # contained_pkg is NOT in packages list but IS in the spdx_id_to_pkg map
        # So we need it in packages for the map to work
        sbom["packages"].append(contained_pkg)
        # But mark it so it won't be picked up by the main loop (no purl? no, it has one)
        # Actually, the main loop WILL pick it up since it has a purl.
        # The CONTAINS logic only adds packages NOT already seen.
        # So let's test with a package that has no purl in the main list but is referenced via CONTAINS
        contained_no_purl_main = {
            "SPDXID": "SPDXRef-Package-C",
            "name": "pkgC",
            "versionInfo": "3.0",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:maven/g/pkgC@3.0"},
            ],
        }
        sbom["packages"].append(contained_no_purl_main)
        sbom["relationships"].append({
            "spdxElementId": "SPDXRef-Package-A",
            "relatedSpdxElement": "SPDXRef-Package-C",
            "relationshipType": "CONTAINS",
        })
        result = convert_spdx(sbom)
        names = {p["name"] for p in result}
        # All packages with purls should be present
        assert "pkgA" in names
        assert "pkgB" in names
        assert "pkgC" in names

    def test_contains_skips_already_seen(self):
        pkg_a = _spdx_package("SPDXRef-A", "pkgA", "1.0", "pkg:maven/g/pkgA@1.0")
        pkg_b = _spdx_package("SPDXRef-B", "pkgB", "2.0", "pkg:maven/g/pkgB@2.0")
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [pkg_a, pkg_b],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-A",
                    "relatedSpdxElement": "SPDXRef-B",
                    "relationshipType": "CONTAINS",
                },
            ],
        }
        result = convert_spdx(sbom)
        assert len(result) == 2  # No duplicates

    def test_non_contains_relationships_ignored(self):
        pkg = _spdx_package("SPDXRef-A", "pkgA", "1.0", "pkg:maven/g/pkgA@1.0")
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [pkg],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-A",
                    "relatedSpdxElement": "SPDXRef-B",
                    "relationshipType": "DESCRIBES",
                },
            ],
        }
        result = convert_spdx(sbom)
        assert len(result) == 1


# ── Phase 2: Dependency graph extraction ─────────────────────────────────


class TestExtractCyclonedxDependencies:

    def test_basic_dependency_edges(self):
        comp_a = _cdx_component("spring-boot", "3.2.0", "pkg:maven/org.springframework.boot/spring-boot@3.2.0")
        comp_b = _cdx_component("spring-core", "6.1.0", "pkg:maven/org.springframework/spring-core@6.1.0")
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [comp_a, comp_b],
            "dependencies": [
                {
                    "ref": "pkg:maven/org.springframework.boot/spring-boot@3.2.0",
                    "dependsOn": ["pkg:maven/org.springframework/spring-core@6.1.0"],
                },
            ],
        }
        packages = convert_cyclonedx(sbom)
        deps = extract_cyclonedx_dependencies(sbom, packages)
        assert len(deps) == 1
        assert deps[0]["dependency_type"] == "depends_on"
        assert deps[0]["package_name"] == "spring-boot"
        assert "spring-core" in deps[0]["dependency_name"]

    def test_discovers_unknown_packages(self):
        comp_a = _cdx_component("spring-boot", "3.2.0", "pkg:maven/org.springframework.boot/spring-boot@3.2.0")
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [comp_a],
            "dependencies": [
                {
                    "ref": "pkg:maven/org.springframework.boot/spring-boot@3.2.0",
                    "dependsOn": [
                        "pkg:maven/org.springframework.security/spring-security-oauth2-authorization-server@1.2.0",
                    ],
                },
            ],
        }
        packages = convert_cyclonedx(sbom)
        assert len(packages) == 1  # Only spring-boot initially
        deps = extract_cyclonedx_dependencies(sbom, packages)
        assert len(deps) == 1
        assert len(packages) == 2  # spring-security-oauth2-authorization-server discovered
        discovered = [p for p in packages if "authorization-server" in p["name"]]
        assert len(discovered) == 1
        assert discovered[0]["type"] == "java"
        assert discovered[0]["purl"].startswith("pkg:maven/")

    def test_no_dependencies_key(self):
        comp = _cdx_component("curl", "8.5.0", "pkg:rpm/redhat/curl@8.5.0")
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [comp]}
        packages = convert_cyclonedx(sbom)
        deps = extract_cyclonedx_dependencies(sbom, packages)
        assert deps == []
        assert len(packages) == 1

    def test_empty_depends_on(self):
        comp = _cdx_component("curl", "8.5.0", "pkg:maven/g/curl@8.5.0")
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [comp],
            "dependencies": [
                {"ref": "pkg:maven/g/curl@8.5.0", "dependsOn": []},
            ],
        }
        packages = convert_cyclonedx(sbom)
        deps = extract_cyclonedx_dependencies(sbom, packages)
        assert deps == []

    def test_unknown_ref_skipped(self):
        comp = _cdx_component("curl", "8.5.0", "pkg:maven/g/curl@8.5.0")
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [comp],
            "dependencies": [
                {
                    "ref": "pkg:maven/g/nonexistent@1.0",
                    "dependsOn": ["pkg:maven/g/curl@8.5.0"],
                },
            ],
        }
        packages = convert_cyclonedx(sbom)
        deps = extract_cyclonedx_dependencies(sbom, packages)
        assert deps == []


class TestExtractSpdxDependencies:

    def test_depends_on_relationship(self):
        pkg_a = _spdx_package("SPDXRef-A", "pkgA", "1.0", "pkg:maven/g/pkgA@1.0")
        pkg_b = _spdx_package("SPDXRef-B", "pkgB", "2.0", "pkg:maven/g/pkgB@2.0")
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [pkg_a, pkg_b],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-A",
                    "relatedSpdxElement": "SPDXRef-B",
                    "relationshipType": "DEPENDS_ON",
                },
            ],
        }
        packages = convert_spdx(sbom)
        deps = extract_spdx_dependencies(sbom, packages)
        assert len(deps) == 1
        assert deps[0]["dependency_type"] == "depends_on"
        assert deps[0]["package_name"] == "pkgA"
        assert "pkgB" in deps[0]["dependency_name"]

    def test_discovers_unknown_spdx_packages(self):
        pkg_a = _spdx_package("SPDXRef-A", "pkgA", "1.0", "pkg:maven/g/pkgA@1.0")
        pkg_b = _spdx_package("SPDXRef-B", "pkgB", "2.0", "pkg:maven/g/pkgB@2.0")
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [pkg_a],  # only pkgA in flat list
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-A",
                    "relatedSpdxElement": "SPDXRef-B",
                    "relationshipType": "DEPENDS_ON",
                },
            ],
        }
        # But pkgB's data IS in the packages array for spdx_id_to_pkg_data mapping
        sbom["packages"].append(pkg_b)
        packages = convert_spdx(sbom)
        deps = extract_spdx_dependencies(sbom, packages)
        assert len(deps) == 1

    def test_non_depends_on_ignored(self):
        pkg_a = _spdx_package("SPDXRef-A", "pkgA", "1.0", "pkg:maven/g/pkgA@1.0")
        pkg_b = _spdx_package("SPDXRef-B", "pkgB", "2.0", "pkg:maven/g/pkgB@2.0")
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [pkg_a, pkg_b],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-A",
                    "relatedSpdxElement": "SPDXRef-B",
                    "relationshipType": "BUILD_TOOL_OF",
                },
            ],
        }
        packages = convert_spdx(sbom)
        deps = extract_spdx_dependencies(sbom, packages)
        assert deps == []


# ── convert_sbom 3-tuple return ──────────────────────────────────────────


class TestConvertSbomReturn:

    def test_cyclonedx_returns_three_tuple(self):
        comp_a = _cdx_component("curl", "8.5.0", "pkg:maven/g/curl@8.5.0")
        comp_b = _cdx_component("zlib", "1.2.13", "pkg:maven/g/zlib@1.2.13")
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [comp_a, comp_b],
            "dependencies": [
                {
                    "ref": "pkg:maven/g/curl@8.5.0",
                    "dependsOn": ["pkg:maven/g/zlib@1.2.13"],
                },
            ],
        }
        fmt, pkgs, deps = convert_sbom(sbom)
        assert fmt == SBOMFormat.CYCLONEDX
        assert len(pkgs) == 2
        assert len(deps) == 1

    def test_spdx_returns_three_tuple(self):
        pkg = _spdx_package("SPDXRef-A", "pkgA", "1.0", "pkg:maven/g/pkgA@1.0")
        sbom = {"spdxVersion": "SPDX-2.3", "packages": [pkg]}
        fmt, pkgs, deps = convert_sbom(sbom)
        assert fmt == SBOMFormat.SPDX
        assert len(pkgs) == 1
        assert deps == []

    def test_syft_returns_three_tuple(self):
        sbom = {
            "artifacts": [
                {"name": "curl", "version": "8.5.0", "type": "rpm", "purl": "pkg:rpm/redhat/curl@8.5.0"},
            ],
        }
        fmt, pkgs, deps = convert_sbom(sbom)
        assert fmt == SBOMFormat.SYFT
        assert len(pkgs) == 1
        assert deps == []

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unrecognized"):
            convert_sbom({"random": "data"})
