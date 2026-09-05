/* Isolate the bundled libmsi child-reference regression from aas-sign wrappers.
 * Run under LeakSanitizer to detect the original leak on successful and failed
 * database opens. Unpatched system libmsi 0.106 is expected to leak here. */
#include <libmsi.h>

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    for (unsigned repeat = 0; repeat < 8; ++repeat) {
        for (int input = 1; input < argc; ++input) {
            GError *error = NULL;
            LibmsiDatabase *db = libmsi_database_new(argv[input], LIBMSI_DB_FLAGS_READONLY, NULL, &error);
            const gboolean success = db != NULL;
            if (db) g_object_unref(db);
            if (error) g_error_free(error);
            /* The second argument may be accepted as an empty database or
             * rejected, depending on the installed libmsi version. Both paths
             * must release every reference acquired while opening it. */
            if (input == 1 && !success) return 1;
        }
    }
    return 0;
}
