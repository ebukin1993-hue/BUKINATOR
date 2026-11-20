#!/usr/bin/env python3
"""Apply the reviewed Android Conscrypt hotfix to extracted v0.3/v1 source.
The original release archives remain immutable."""
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
which = sys.argv[2]
assert which in ("control", "diagnostics")
java = root / "app/src/main/java/com/ballucontrol/local"
shutil.copyfile("ballu-hotfix/SyncleoCrypto.java", java / "SyncleoCrypto.java")
gradle = root / "app/build.gradle"
build = gradle.read_text()

def replace_required(s, old, new):
    if old not in s:
        raise RuntimeError("Expected original pattern not found: " + old[:60])
    return s.replace(old, new)

if which == "control":
    build = replace_required(build, "versionCode 3", "versionCode 4")
    build = replace_required(build, "versionName '0.3.0'", "versionName '0.4.0'")
    activity = java / "MainActivity.java"
    s = activity.read_text()
    s = replace_required(s, "Ballu Control · версия 0.2", "Ballu Control · версия 0.4")
    activity.write_text(s)
else:
    build = replace_required(build, "versionCode 1", "versionCode 2")
    build = replace_required(build, "versionName '1.0.0'", "versionName '1.1.0'")
    activity = java / "DiagnosticActivity.java"
    s = activity.read_text()
    s = replace_required(s, "Ballu Diagnostics 1.0.0", "Ballu Diagnostics 1.1.0")
    s = replace_required(
        s,
        """            SyncleoSession session=new SyncleoSession(device.publicKey);
            if(session.handshake(new byte[16]).length!=53)throw new IllegalStateException("неожиданная длина handshake");
            event("OK","Локальная криптография X25519/SHA-256/AES-CBC доступна");
""",
        """            final SyncleoSession session;
            try {
                session=new SyncleoSession(device.publicKey);
                event("OK","X25519: ключи сеанса и SHA-256 подготовлены");
            } catch(Exception crypt) {
                event("ERROR","X25519: "+safeError(crypt));
                finish("Ошибка обмена X25519");return;
            }
            try {
                if(session.handshake(new byte[16]).length!=53)
                    throw new IllegalStateException("Unexpected handshake frame");
                event("OK","AES-128-CBC: подготовка handshake прошла успешно");
            } catch(Exception crypt) {
                event("ERROR","AES-CBC/handshake: "+safeError(crypt));
                finish("Ошибка AES-CBC");return;
            }
"""
    )
    s = replace_required(
        s,
        """    private static String safeError(Exception e){
        String name=e.getClass().getSimpleName();
        // Do not log untrusted exception content (can leak provided credentials).
        return name;
    }""",
        """    private static String safeError(Exception e){
        // Only stage name and exception class are logged, never keys or tokens.
        if(e instanceof SyncleoCrypto.CryptoStageException){
            SyncleoCrypto.CryptoStageException x=(SyncleoCrypto.CryptoStageException)e;
            return x.stage+"/"+(x.getCause()==null ? "Unknown" : x.getCause().getClass().getSimpleName());
        }
        return e.getClass().getSimpleName();
    }"""
    )
    activity.write_text(s)
gradle.write_text(build)
print("Applied Ballu Android 16 XDH fix to", which, root)
