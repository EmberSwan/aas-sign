# Bundled libmsi fixes

`libmsi-gsf-child-ref.patch` fixes an ownership bug in msitools 0.106's
`libmsi/libmsi-database.c`. `cache_infile_structure()` obtains a new GSF child
reference on each iteration, but releases it only for ordinary streams. Table
streams, `_StringPool`, `_StringData`, embedded storages, and early exits retain
the reference and consequently the underlying compound-file storage.

The patch releases that temporary reference at scope exit. Database stream and
storage caches retain their own references. It changes no file-format behavior.
Apply it only to the private dependency build copy; the bundled upstream source
archive and the osslsigncode submodule remain unchanged.

`libmsi-string-ownership.patch` frees allocated string-table entries even when
their MSI reference counts are zero, both at destruction and before slot reuse.
The malformed `string-refcount.msi` corpus seed exercises this second leak.

`libmsi-table-cleanup.patch` lets failed table initialization release a null
column array and rejects zero-sized rows before division. These guards keep
malformed table metadata on the ordinary error path.

`libmsi-summary-bounds.patch` checks summary-section and property bounds before
reading them and propagates malformed metadata as an ordinary library error.
The `missing-column.msi` and `summary-offset.msi` corpus seeds exercise the
table-cleanup and summary-offset failures, respectively.

`tests/libmsi_ownership_test.c` opens and closes a valid installer and the
minimal CFB corpus seed directly through libmsi, without any aas-sign wrapper.
It is a regression test when built with AddressSanitizer/LeakSanitizer and linked
against the patched dependency. Arguments are `tests/fixtures/recursive.msi` and
`fuzz/corpus/msi/minimal-msi-v3.msi`, followed by optional additional corpus files.

`DEPS=LOCAL` deliberately uses the installed distribution library. An unpatched
libmsi 0.106 therefore still has these leaks and malformed-input failures during
MSI fuzzing. Use the patched `DEPS=FETCH` dependencies for the recorded sanitizer
regressions, or update the system library with these fixes. Do not disable
ASan, UBSan, or leak checking globally to hide the dependency finding.
