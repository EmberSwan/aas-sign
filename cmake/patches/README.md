# Bundled libmsi ownership fix

`libmsi-gsf-child-ref.patch` fixes an ownership bug in msitools 0.106's
`libmsi/libmsi-database.c`. `cache_infile_structure()` obtains a new GSF child
reference on each iteration, but releases it only for ordinary streams. Table
streams, `_StringPool`, `_StringData`, embedded storages, and early exits retain
the reference and consequently the underlying compound-file storage.

The patch releases that temporary reference at scope exit. Database stream and
storage caches retain their own references. It changes no file-format behavior.
Apply it only to the private dependency build copy; the bundled upstream source
archive and the osslsigncode submodule remain unchanged.

`tests/libmsi_ownership_test.c` opens and closes a valid installer and the
minimal CFB corpus seed directly through libmsi, without any aas-sign wrapper.
It is a regression test when built with AddressSanitizer/LeakSanitizer and linked
against the patched dependency. Arguments are `tests/fixtures/recursive.msi` and
`fuzz/corpus/msi/minimal-msi-v3.msi`, in that order.

`DEPS=LOCAL` deliberately uses the installed distribution library. An unpatched
libmsi 0.106 therefore still reports this upstream leak during MSI fuzzing and
this direct regression test. Use the patched `DEPS=FETCH` dependencies for a
clean LeakSanitizer run, or update the system library with this fix. Do not disable
ASan, UBSan, or leak checking globally to hide the dependency finding.
