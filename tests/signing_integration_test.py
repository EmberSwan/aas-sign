#!/usr/bin/env python3
"""Credential-free interoperability against the real companion, never a mock CLI."""
import base64
import hashlib
import http.server
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile
from xml.sax.saxutils import escape

DRIVER, COMPANION, SOURCE = map(lambda x: pathlib.Path(x).resolve(), sys.argv[1:4])
OPENSSL = shutil.which("openssl")
MSI_FACTORY = pathlib.Path(sys.argv[4]).resolve() if len(sys.argv) > 4 else None


def run(*args, ok=True):
    result = subprocess.run(list(map(str, args)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if (result.returncode == 0) != ok:
        raise AssertionError(f"Unexpected exit {result.returncode}: {args}\n{result.stdout.decode(errors='replace')}")
    return result.stdout.decode(errors="replace")


def blockmap(entries):
    rows = []
    for name, data in entries.items():
        blocks = ''.join(f'<Block Hash="{base64.b64encode(hashlib.sha256(data[i:i+65536]).digest()).decode()}"/>'
                         for i in range(0, len(data), 65536))
        rows.append(f'<File Name="{escape(name)}" Size="{len(data)}" LfhSize="{30+len(name.encode())}">{blocks}</File>')
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
            'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">' + ''.join(rows) + '</BlockMap>').encode()


def bundle(package, out):
    name = 'app.msix'
    data = package.read_bytes()
    manifest = ('<?xml version="1.0" encoding="UTF-8"?>'
        '<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="1.0">'
        '<Identity Name="osslsigncode" Publisher="E=osslsigncode@example.com, CN=Certificate, OU=CSP, '
        'O=osslsigncode, L=Warsaw, S=Mazovia Province, C=PL" Version="2.5.0.0"/>'
        f'<Packages><Package Type="application" Version="2.5.0.0" Architecture="x64" '
        f'FileName="{name}" Offset="{30+len(name)}" Size="{len(data)}">'
        '<Resources><Resource Language="en-us"/></Resources></Package></Packages></Bundle>').encode()
    manifest_name = 'AppxMetadata/AppxBundleManifest.xml'
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_STORED) as z:
        z.writestr(name, data)
        z.writestr(manifest_name, manifest)
        z.writestr('AppxBlockMap.xml', blockmap({manifest_name: manifest}))
        z.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="msix" ContentType="application/vnd.ms-appx"/>'
            '<Override PartName="/AppxMetadata/AppxBundleManifest.xml" ContentType="application/vnd.ms-appx.bundlemanifest+xml"/>'
            '<Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/></Types>', compress_type=zipfile.ZIP_DEFLATED)


with tempfile.TemporaryDirectory(prefix="aas signing test ") as directory:
    root = pathlib.Path(directory)
    req_config = root / 'req.cnf'
    req_config.write_text('[req]\ndistinguished_name=dn\n[dn]\n')
    key, cert, der = [root / n for n in ('key.pem', 'cert.pem', 'cert.der')]
    subject = '/C=PL/ST=Mazovia Province/L=Warsaw/O=osslsigncode/OU=CSP/CN=Certificate/emailAddress=osslsigncode@example.com'
    run(OPENSSL, 'req', '-config', req_config, '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
        '-subj', subject, '-addext', 'extendedKeyUsage=codeSigning', '-keyout', key, '-out', cert)
    run(OPENSSL, 'x509', '-in', cert, '-outform', 'DER', '-out', der)
    fixtures = SOURCE / 'modules/osslsigncode/tests/files'

    def sign(path, *args, ok=True):
        return run(DRIVER, COMPANION, key, der, path, *args, ok=ok)

    def verify(path, timestamp_ca=None):
        args = [COMPANION, 'verify', '-CAfile', cert, '-ignore-cdp', '-ignore-crl']
        if timestamp_ca:
            args += ['-TSA-CAfile', timestamp_ca]
        output = run(*args, '-in', path)
        if timestamp_ca:
            # osslsigncode can exit successfully after a timestamp trust failure
            # when the code-signing certificate is still valid at the current time.
            assert 'Timestamp Server Signature verification: ok' in output, output
        return output

    originals = {}
    for ext, fixture in [('exe', 'unsigned.exe'), ('msi', 'unsigned.msi'), ('msix', 'unsigned.256appx')]:
        path = root / ('artifact space é.' + ext)
        shutil.copyfile(fixtures / fixture, path)
        originals[ext] = path.read_bytes()
        dump = root / (ext + '.der')
        sign(path, '--dump-cms', dump, '--recursive' if ext != 'msi' else '--msi-dse')
        verify(path)
        extracted = root / (ext + '-extracted.der')
        run(COMPANION, 'extract-signature', '-in', path, '-out', extracted)
        assert dump.read_bytes() == extracted.read_bytes()
        # Existing outer signatures are replaced, including enhanced -> basic.
        sign(path)
        verify(path)
        if ext == 'msi':
            sign(path, '--msi-dse')
            verify(path)
        before = path.read_bytes()
        sign(path, '--fail-sign', '1', ok=False)
        assert before == path.read_bytes(), 'failure changed the original'
        assert '--dump-cms must not' in sign(path, '--dump-cms', path, ok=False)
        assert before == path.read_bytes(), 'dump alias changed original'
        if ext == 'msix':
            unsigned = root / 'original.msix'
            unsigned.write_bytes(originals[ext])
            with zipfile.ZipFile(unsigned) as a, zipfile.ZipFile(path) as b:
                for name in a.namelist():
                    if name != '[Content_Types].xml':
                        assert a.read(name) == b.read(name), name

    if MSI_FACTORY:
        unsigned_pe, signed_pe = root / 'unsigned-payload.exe', root / 'signed-payload.exe'
        unsigned_pe.write_bytes(originals['exe'])
        signed_pe.write_bytes(originals['exe'])
        sign(signed_pe)
        recursive = root / 'recursive.msi'
        run(MSI_FACTORY, '--create-fixture', recursive, unsigned_pe, signed_pe)
        before = recursive.read_bytes()
        sign(recursive, '--recursive', '--fail-sign', '2', ok=False)
        assert recursive.read_bytes() == before, 'payload failure changed original MSI'
        # Three payloads and then the outer MSI require four signing calls.
        sign(recursive, '--recursive', '--fail-sign', '4', ok=False)
        assert recursive.read_bytes() == before, 'outer failure changed original MSI'
        output = sign(recursive, '--recursive', '--msi-dse')
        assert '3 signed, 1 preserved' in output
        verify(recursive)
        extracted_dir = root / 'extracted'
        extracted_dir.mkdir()
        run(MSI_FACTORY, '--extract-fixture', recursive, extracted_dir)
        for payload in extracted_dir.iterdir():
            verify(payload)
        assert (extracted_dir / 'PreservedDll').read_bytes() == signed_pe.read_bytes()
        assert '0 signed, 4 preserved' in sign(recursive, '--recursive')
        verify(recursive)

    package = root / 'inner.msix'
    package.write_bytes(originals['msix'])
    bundled = root / 'package.msixbundle'
    bundle(package, bundled)
    sign(bundled, '--recursive')
    verify(bundled)
    with zipfile.ZipFile(bundled) as z:
        assert z.read('app.msix') == originals['msix']
    sign(bundled)
    verify(bundled)

    # The pinned upstream rewrites content types using Deflate but preserves
    # its old method flag. Fail closed for the stored-content-types edge case.
    stored = root / 'stored-content-types.msix'
    with zipfile.ZipFile(package) as original, zipfile.ZipFile(stored, 'w') as target:
        for entry in original.infolist():
            data = original.read(entry.filename)
            if entry.filename == '[Content_Types].xml':
                entry.compress_type = zipfile.ZIP_STORED
            target.writestr(entry, data)
    before = stored.read_bytes()
    sign(stored, ok=False)
    assert stored.read_bytes() == before

    unsupported = root / 'sha512.msix'
    shutil.copyfile(fixtures / 'unsigned.512appx', unsupported)
    before = unsupported.read_bytes()
    assert 'SHA-256 required' in sign(unsupported, ok=False)
    assert unsupported.read_bytes() == before

    # The fixture's timestamp service is local and isolated from Azure/public TSA.
    tsa_key, tsa_cert = root / 'tsa.key', root / 'tsa.pem'
    run(OPENSSL, 'req', '-config', req_config, '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
        '-subj', '/CN=Local fixture TSA', '-addext', 'extendedKeyUsage=critical,timeStamping',
        '-addext', 'keyUsage=critical,digitalSignature', '-keyout', tsa_key, '-out', tsa_cert)
    (root / 'tsa.serial').write_text('01\n')
    config = root / 'tsa.cnf'
    config.write_text('[tsa]\ndefault_tsa=local\n[local]\nserial=' + (root / 'tsa.serial').as_posix() +
        '\ncrypto_device=builtin\nsigner_cert=' + tsa_cert.as_posix() + '\nsigner_key=' + tsa_key.as_posix() +
        '\nsigner_digest=sha256\ndefault_policy=1.2.3.4\ndigests=sha256\naccuracy=secs:1\n'
        'ordering=no\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n')

    class TSA(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            request, response = root / 'request.tsq', root / 'response.tsr'
            request.write_bytes(self.rfile.read(int(self.headers['Content-Length'])))
            run(OPENSSL, 'ts', '-reply', '-config', config, '-queryfile', request, '-out', response)
            data = response.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'application/timestamp-reply')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), TSA)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for ext in ('exe', 'msi', 'msix', 'msixbundle'):
            target = root / ('timestamp.' + ext)
            target.write_bytes(originals[ext] if ext in originals else bundled.read_bytes())
            dump = root / ('timestamp-' + ext + '.der')
            sign(target, '--timestamp-url', f'http://127.0.0.1:{server.server_port}/', '--dump-cms', dump,
                 *(['--msi-dse'] if ext == 'msi' else []))
            verify(target, tsa_cert)
            # szOID_RFC3161_counterSign remains present in the final dumped CMS.
            assert bytes.fromhex('060a2b060104018237030301') in dump.read_bytes()
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
    if os.name == 'nt':
        run('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            SOURCE / 'tests/windows_install_test.ps1', '-Driver', DRIVER, '-Companion', COMPANION,
            '-Key', key, '-CertDer', der, '-Workspace', root)
    assert not list(root.glob('aas-sign-*')), 'staging workspaces leaked'
print('Detached PE/MSI/MSIX/bundle signing, timestamping and rollback passed')
