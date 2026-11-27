import re

from . import engines


def rebuild(root, output, original=None, *, engine="apktool", jar=None):
    """Rebuild a decoded tree.  Kept for API compatibility with v0.1-v0.3."""
    if engine == "apkeditor":
        if not jar:
            raise engines.EngineError("APKEditor rebuild requires a jar path")
        engines.rebuild_apkeditor(jar, root, output)
    else:
        try:
            engines.rebuild_apktool(root, output)
        except engines.EngineError as error:
            hint = ""
            if original is not None:
                hint = "\nRetry clean with --smali-only to preserve compiled resources."
            elif engines.resource_failure(str(error)):
                hint = "\nRetry clean with --engine apkeditor to avoid aapt2."
            raise engines.EngineError(str(error) + hint) from error
    if original:
        # Only transplant assembled DEX. Even unknown resource encodings survive.
        from . import repack

        with __import__("zipfile").ZipFile(output) as built:
            replacements = {
                name: built.read(name) for name in built.namelist()
                if re.fullmatch(r"classes(?:[2-9]|[1-9]\d+)?\.dex", name)
            }
        merged = output.with_suffix(".merged.apk")
        repack.repack(original, merged, replace=replacements)
        merged.replace(output)
    return output
