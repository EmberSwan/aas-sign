# Corpus provenance

The PE stubs and minimal MSI compound file are project-generated seeds.
X.509 seeds are fixture certificates with no production signing identity.
`msi/installer.msi` is the unsigned test installer from the recorded
`modules/osslsigncode` submodule. `cms_indirect/pe.der` and `msix.der` were
produced using that submodule's `extract-data` command and its unsigned PE
and SHA-256 APPX fixtures. See the submodule's COPYING.txt and LICENSE.txt.

The MSI reconstruction tests also generate a complete multi-cabinet fixture;
see tests/fixtures/README.md for its source and regeneration instructions.
`msi/string-refcount.msi` is a malformed mutation of that generated fixture,
retained as a regression for libmsi string-table cleanup.
`msi/missing-column.msi` and `msi/summary-offset.msi` are further mutations
retained for libmsi table-cleanup and summary-bounds regressions.
