import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from apk_surgeon import audit, engines, selective, sinkhole
from apk_surgeon import recipe as recipes
from apk_surgeon.scanner import ANDROID, parse_manifest

MANIFEST = f'''<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example">
    <application android:label="Fixture"><activity android:name=".Main"/></application>
</manifest>'''


def write_recipe(tmp_path, text, name="recipe.yml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_recipe_loads_methods_and_components(tmp_path):
    path = write_recipe(tmp_path, """
version: 1
package_prefixes:
  - com.example.tracker
methods:
  - class: Lcom/example/tracker/Track;
    method: send(Ljava/lang/String;)V
  - Lcom/example/tracker/More;->log()V
disable_components:
  - com.example.tracker.Receiver
sinkhole_domains:
  - api.segment.io
""")
    recipe = recipes.load(path)
    assert recipe.package_prefixes == ["com.example.tracker"]
    assert recipe.methods["Lcom/example/tracker/Track;"] == {"send(Ljava/lang/String;)V"}
    assert "log()V" in recipe.methods["Lcom/example/tracker/More;"]
    assert recipe.disable_components == ["com.example.tracker.Receiver"]
    assert recipe.sinkhole_domains == ["api.segment.io"]


@pytest.mark.parametrize(("body", "message"), [
    ("unknown: 1\n", "unknown field"),
    ("version: 2\n", "unsupported version"),
    ("methods:\n  - nope\n", "full"),
    ("methods:\n  - class: Track\n    method: send()V\n", "smali descriptor"),
    ("package_prefixes: [not a package]\n", "dotted Java package"),
    ("disable_components: [bad name!]\n", "not a class name"),
    ("sinkhole_domains: [googleapis.com]\n", "protected shared domains"),
    ("sinkhole_domains: [example.com]\n", "pure-telemetry allowlist"),
    ("- just\n- a list\n", "mapping"),
    ("", "empty"),
])
def test_recipe_validation(tmp_path, body, message):
    with pytest.raises(ValueError, match=message):
        recipes.load(write_recipe(tmp_path, body))


def test_recipe_yaml_syntax_error_reports_line(tmp_path):
    with pytest.raises(ValueError, match="invalid YAML"):
        recipes.load(write_recipe(tmp_path, "version: 1\nmethods: [\n"))


def test_recipe_missing_file():
    with pytest.raises(ValueError, match="cannot read file"):
        recipes.load(Path("/nonexistent/recipe.yml"))


def test_trust_user_ca_creates_config_and_manifest_attribute(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(MANIFEST)
    changes, package = audit.trust_user_ca(tmp_path)
    assert package == "org.example"
    config = tmp_path / "res/xml/apk_surgeon_network_security_config.xml"
    assert config in changes and '<certificates src="user" />' in changes[config]
    (tmp_path / "AndroidManifest.xml").write_text(changes[tmp_path / "AndroidManifest.xml"])
    tree = parse_manifest(tmp_path / "AndroidManifest.xml")
    assert tree.getroot().find("application").get(ANDROID + "networkSecurityConfig") == (
        "@xml/apk_surgeon_network_security_config")


def test_trust_user_ca_merges_an_existing_config(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(MANIFEST.replace(
        '<application', '<application android:networkSecurityConfig="@xml/existing"'))
    existing = tmp_path / "res/xml/existing.xml"
    existing.parent.mkdir(parents=True)
    existing.write_text('<network-security-config><domain-config cleartextTrafficPermitted="true">'
                        '<domain includeSubdomains="true">example.com</domain><trust-anchors>'
                        '<certificates src="system"/></trust-anchors></domain-config>'
                        '</network-security-config>')
    changes, _ = audit.trust_user_ca(tmp_path)
    assert set(changes) == {existing}
    merged = changes[existing]
    assert 'src="user"' in merged
    assert merged.count('src="system"') == 2
    assert 'example.com' in merged


def test_trust_user_ca_missing_existing_config_is_an_error(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(MANIFEST.replace(
        '<application', '<application android:networkSecurityConfig="@xml/existing"'))
    with pytest.raises(ValueError, match="not in the decoded resources"):
        audit.trust_user_ca(tmp_path)


def test_allow_screenshots_patches_only_literal_flag_secure():
    plain = '''.method public a()V
    .locals 2
    const/16 v0, 0x2000
    invoke-virtual {p0, v0}, Landroid/view/Window;->addFlags(I)V
    return-void
.end method
'''
    edited, count = audit.allow_screenshots_text(plain)
    assert count == 1 and "const/16 v0, 0x0" in edited
    dynamic = '''.method public b(I)V
    .locals 2
    const/16 v0, 0x2000
    or-int/2addr v0, p1
    invoke-virtual {p0, v0, v0}, Landroid/view/Window;->setFlags(II)V
    return-void
.end method
'''
    assert audit.allow_screenshots_text(dynamic) == (dynamic, 0)
    other = '''.method public c()V
    .locals 2
    const/16 v0, 0x2000
    invoke-virtual {p0, v0}, Landroid/view/Window;->clearFlags(I)V
    return-void
.end method
'''
    assert audit.allow_screenshots_text(other) == (other, 0)


def test_allow_screenshots_walks_decoded_tree(tmp_path):
    source = tmp_path / "smali/a.smali"
    source.parent.mkdir()
    source.write_text('''.method public a()V
    .locals 1
    const/16 v0, 0x2000
    invoke-virtual {p0, v0, v0}, Landroid/view/Window;->setFlags(II)V
    return-void
.end method
''')
    changes, count = audit.allow_screenshots(tmp_path)
    assert count == 1 and changes[source]


def test_apkeditor_command_and_resolution(tmp_path, monkeypatch):
    jar = tmp_path / "APKEditor-1.4.9.jar"
    jar.write_bytes(b"jar")
    assert engines.command(jar, "d")[:3] == ["java", "-jar", str(jar)]
    wrapper = tmp_path / "apkeditor"
    wrapper.write_text("#!/bin/sh")
    assert engines.command(wrapper, "b")[0] == str(wrapper)
    monkeypatch.delenv(engines.ENV_JAR, raising=False)
    assert engines.resolve_apkeditor(str(jar)) == jar.resolve()
    with pytest.raises(engines.EngineError, match="not found"):
        engines.resolve_apkeditor(str(tmp_path / "missing.jar"))
    monkeypatch.setenv(engines.ENV_JAR, str(jar))
    assert engines.resolve_apkeditor() == jar.resolve()
    monkeypatch.delenv(engines.ENV_JAR)
    monkeypatch.setattr(engines.shutil, "which", lambda name: str(wrapper))
    assert engines.resolve_apkeditor() == wrapper.resolve()
    monkeypatch.setattr(engines.shutil, "which", lambda name: None)
    assert engines.resolve_apkeditor() is None


def test_doctor_note_for_missing_apkeditor():
    note = engines.doctor_note(None)
    assert "--apkeditor-jar" in note and "optional" in note and engines.DOWNLOAD in note


def test_resource_failure_classification():
    assert engines.resource_failure("brut.androlib.res.decoder.AXmlResourceParser: aapt2 error")
    assert engines.resource_failure("Invalid resource name: res/a-b.xml")
    assert not engines.resource_failure("error: invalid smali instruction")


def test_decode_apkeditor_retries_xml_json_raw(tmp_path, monkeypatch):
    calls = []

    def fake_run(argv, what):
        calls.append(argv)
        if "-t" in argv and argv[argv.index("-t") + 1] == "xml":
            raise engines.EngineError("APKEditor decode (-t xml) failed.\ninvalid resource")
        Path(argv[argv.index("-o") + 1]).mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(engines, "run", fake_run)
    result = engines.decode_apkeditor(tmp_path / "a.jar", tmp_path / "in.apk", tmp_path / "out")
    assert result.decode_type == "json"
    assert "not editable" in result.notes[0]
    assert [call[call.index("-t") + 1] for call in calls] == ["xml", "json"]
    assert result.root.exists()


def test_decode_apkeditor_reports_all_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(engines, "run", Mock(side_effect=engines.EngineError("boom")))
    with pytest.raises(engines.EngineError, match="could not decode"):
        engines.decode_apkeditor(tmp_path / "a.jar", tmp_path / "in.apk", tmp_path / "out")


def test_merge_uses_clean_meta(tmp_path, monkeypatch):
    seen = {}

    def fake_run(argv, what):
        seen["argv"] = argv
        Path(argv[argv.index("-o") + 1]).write_bytes(b"pk")

    monkeypatch.setattr(engines, "run", fake_run)
    engines.merge_splits(tmp_path / "a.jar", tmp_path / "splits", tmp_path / "merged.apk")
    assert "-clean-meta" in seen["argv"]
    assert seen["argv"][-1] == "-f"
    assert "m" in seen["argv"][:4]


def test_dex_candidates_and_selective_patch(tmp_path, monkeypatch, dex_bytes):
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", dex_bytes(["Lcom/example/Main;"]), compress_type=zipfile.ZIP_STORED)
        archive.writestr("classes2.dex", dex_bytes(["Lcom/google/firebase/analytics/FirebaseAnalytics;"]))
        archive.writestr("resources.arsc", b"table", compress_type=zipfile.ZIP_STORED)
        archive.writestr("META-INF/CERT.SF", b"stale")
    assert selective.dex_candidates(apk, ["com/google/firebase/analytics"]) == ["classes2.dex"]

    def fake_decode(source, root, *, no_res=False):
        smali = Path(root) / "smali" / "com" / "google" / "firebase" / "analytics" / "FirebaseAnalytics.smali"
        smali.parent.mkdir(parents=True)
        smali.write_text(".class public Lcom/google/firebase/analytics/FirebaseAnalytics;\n"
                         ".method public logEvent(Ljava/lang/String;Landroid/os/Bundle;)V\n"
                         "    .locals 1\n    return-void\n.end method\n")
        return engines.DecodeResult("apktool", Path(root))

    built = tmp_path / "built" / "built.apk"
    built.parent.mkdir()

    def fake_rebuild(root, output):
        with zipfile.ZipFile(built, "w") as archive:
            archive.writestr("classes.dex", dex_bytes(["patched"]))
        Path(output).write_bytes(built.read_bytes())

    monkeypatch.setattr(engines, "decode_apktool", fake_decode)
    monkeypatch.setattr(engines, "rebuild_apktool", fake_rebuild)

    def transform(path, text):
        return text.replace("return-void", "return-void\n    # patched"), ["method"]

    output, changed, found = selective.patch_dex(apk, tmp_path / "work", "classes2.dex", transform)
    assert output != apk and changed and found
    with zipfile.ZipFile(output) as archive:
        assert archive.read("classes2.dex") == dex_bytes(["patched"])
        assert archive.read("resources.arsc") == b"table"
        info = {item.filename: item for item in archive.infolist()}
        assert info["resources.arsc"].compress_type == zipfile.ZIP_STORED
        assert info["classes.dex"].compress_type == zipfile.ZIP_STORED
        assert "META-INF/CERT.SF" not in info


def test_selective_patch_is_a_noop_without_changes(tmp_path, monkeypatch, dex_bytes):
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes2.dex", dex_bytes(["x"]))
    def fake_decode(source, root, *, no_res=False):
        (Path(root) / "smali").mkdir(parents=True)
        (Path(root) / "smali" / "a.smali").write_text(".class public La;\n")
        return engines.DecodeResult("apktool", Path(root))

    monkeypatch.setattr(engines, "decode_apktool", fake_decode)
    output, changed, found = selective.patch_dex(apk, tmp_path / "work", "classes2.dex",
                                                 lambda path, text: (text, []))
    assert output == apk and changed == [] and found == []


def test_sinkhole_validate_recipe_domains_normalizes():
    assert sinkhole.validate_recipe_domains(["API.Segment.io"]) == ["api.segment.io"]
    with pytest.raises(sinkhole.DeniedDomain):
        sinkhole.validate_recipe_domains(["sub.googleapis.com"])


def test_prepare_limits_sinkhole_to_matched_dex(tmp_path, monkeypatch, dex_bytes):
    from apk_surgeon import cli

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", dex_bytes(["https://app-measurement.com/a"]))
        archive.writestr("classes2.dex", dex_bytes(["Lcom/example/Other;"]))
    root = tmp_path / "decoded"
    for directory, body in (("smali", '.method public a()V\n    .locals 1\n    const-string v0, '
                                        '"https://app-measurement.com/a"\n    return-void\n.end method\n'),
                            ("smali_classes2", '.method public b()V\n    .locals 1\n    const-string v0, '
                                               '"https://api.mixpanel.com/x"\n    return-void\n.end method\n')):
        (root / directory).mkdir(parents=True)
        (root / directory / "a.smali").write_text(body)
    monkeypatch.setattr(cli.engines, "decode_apktool", lambda *a, **k: engines.DecodeResult("apktool", root))
    args = SimpleNamespace(engine="apktool", sinkhole=True, allow_screenshots=False, trust_user_ca=False,
                           strip_ad_permissions=False, disable_providers=False, smali_only=False)
    result = cli.prepare(args, apk, tmp_path / "work", "apktool", apkeditor=None, recipe=None,
                         notes=[], bypass=False)
    assert result["stats"]["sinkholed"] == ["https://app-measurement.com/a"]
    edited = result["changes"][root / "smali" / "a.smali"]
    assert sinkhole.SINKHOLE in edited
    assert root / "smali_classes2" / "a.smali" not in result["changes"]


def test_clean_meta_only_on_merge(tmp_path, monkeypatch):
    seen = []

    def fake_run(argv, what):
        seen.append(argv)
        if "-o" in argv:
            out = Path(argv[argv.index("-o") + 1])
            if "decode" in what.lower():
                out.mkdir(parents=True, exist_ok=True)
            else:
                out.write_bytes(b"pk")

    monkeypatch.setattr(engines, "run", fake_run)
    jar = tmp_path / "a.jar"
    engines.decode_apkeditor(jar, tmp_path / "in.apk", tmp_path / "dec")
    engines.rebuild_apkeditor(jar, tmp_path / "dec", tmp_path / "out.apk")
    engines.merge_splits(jar, tmp_path / "splits", tmp_path / "merged.apk")
    assert "-clean-meta" not in seen[0]
    assert "-clean-meta" not in seen[1]
    assert "-clean-meta" in seen[2]


def test_selective_patch_handles_classes2_output_and_refuses_dex041(tmp_path, monkeypatch, dex_bytes):
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", dex_bytes(["Lcom/example/Main;"]))
        archive.writestr("classes2.dex", dex_bytes(["Lcom/google/firebase/analytics/FirebaseAnalytics;"]))

    def fake_decode(source, root, *, no_res=False):
        smali = Path(root) / "smali_classes2" / "com" / "google" / "firebase" / "analytics" / "FA.smali"
        smali.parent.mkdir(parents=True)
        smali.write_text(".class public Lcom/google/firebase/analytics/FA;\n")
        return engines.DecodeResult("apktool", Path(root))

    def fake_rebuild(root, output):
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("classes2.dex", dex_bytes(["patched-2"]))

    monkeypatch.setattr(engines, "decode_apktool", fake_decode)
    monkeypatch.setattr(engines, "rebuild_apktool", fake_rebuild)
    output, changed, _ = selective.patch_dex(
        apk, tmp_path / "work", "classes2.dex", lambda p, t: (t + "# ok\n", ["ok"])
    )
    assert changed and zipfile.ZipFile(output).read("classes2.dex") == dex_bytes(["patched-2"])

    dex041 = tmp_path / "v41.apk"
    with zipfile.ZipFile(dex041, "w") as archive:
        archive.writestr("classes.dex", dex_bytes(["a"], version=41))
    with pytest.raises(selective.SelectiveError, match="041"):
        selective.patch_dex(dex041, tmp_path / "w41", "classes.dex", lambda p, t: (t, []))


def test_prepare_parses_manifest_for_assess(tmp_path, monkeypatch, dex_bytes):
    from apk_surgeon import cli

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", dex_bytes(["a"]))
    root = tmp_path / "decoded"
    (root / "smali").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example"><application>'
        '<meta-data android:name="com.google.android.gms.ads.APPLICATION_ID" android:value="ca-app-pub"/>'
        "</application></manifest>"
    )
    monkeypatch.setattr(cli.engines, "decode_apktool", lambda *a, **k: engines.DecodeResult("apktool", root))
    args = SimpleNamespace(engine="apktool", sinkhole=False, allow_screenshots=False, trust_user_ca=False,
                           strip_ad_permissions=False, disable_providers=False, smali_only=False)
    result = cli.prepare(args, apk, tmp_path / "work", "apktool", apkeditor=None, recipe=None,
                         notes=[], bypass=False)
    assert "Google AdMob" in result["evidence"]


def test_scan_json_runs_exodus_and_bundle_passes_base_and_parts(tmp_path, monkeypatch, capsys, dex_bytes):
    import json

    from apk_surgeon import cli

    base = tmp_path / "base.apk"
    split = tmp_path / "split_arm64_v8a.apk"
    for path, extra in ((base, {"classes.dex": dex_bytes(["a"])}),
                        (split, {"lib/arm64-v8a/libflutter.so": b"\x7fELF"})):
        with zipfile.ZipFile(path, "w") as archive:
            for k, v in extra.items():
                archive.writestr(k, v)
    bundle = tmp_path / "app.xapk"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.write(base, "base.apk")
        archive.write(split, "split_arm64_v8a.apk")

    root = tmp_path / "decoded"
    (root / "smali").mkdir(parents=True)
    (root / "smali" / "a.smali").write_text(".class public Lcom/example/Tracker;\n")
    db = tmp_path / "exodus.json"
    db.write_text(json.dumps({"trackers": {"1": {"name": "ExampleTracker", "code_signature": "com\\.example\\.Tracker"}}}))

    seen = {}

    def fake_decode(apk_arg, out_root, *, no_res=False):
        seen["decoded_apk"] = apk_arg
        return engines.DecodeResult("apktool", root)

    monkeypatch.setattr(cli, "unpack", lambda src, work: [base, split])
    monkeypatch.setattr(cli.engines, "decode_apktool", fake_decode)
    rc = cli.main(["scan", str(bundle), "--tracker-db", str(db), "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert seen["decoded_apk"] == base
    assert payload["exodus"] == ["ExampleTracker"]
    assert payload["detected_frameworks"] == ["Flutter"]


def test_rebuild_original_splices_dex_and_cli_passes_original_on_smali_only(tmp_path, monkeypatch, dex_bytes):
    from apk_surgeon import cli, rebuild

    orig = tmp_path / "orig.apk"
    with zipfile.ZipFile(orig, "w") as archive:
        archive.writestr("resources.arsc", b"original-table", compress_type=zipfile.ZIP_STORED)
        archive.writestr("META-INF/CERT.SF", b"stale")
        archive.writestr("classes.dex", dex_bytes(["old"]))

    def fake_rebuild_apktool(root, output):
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("resources.arsc", b"broken-table")
            archive.writestr("classes.dex", dex_bytes(["new"]))
        return output

    monkeypatch.setattr(engines, "rebuild_apktool", fake_rebuild_apktool)
    out = tmp_path / "rebuilt.apk"
    rebuild.rebuild(tmp_path / "root", out, original=orig, engine="apktool")
    with zipfile.ZipFile(out) as archive:
        assert archive.read("resources.arsc") == b"original-table"
        assert archive.read("classes.dex") == dex_bytes(["new"])
        assert "META-INF/CERT.SF" not in archive.namelist()

    seen = {}
    monkeypatch.setattr(rebuild, "rebuild", lambda r, o, original=None, **k: seen.setdefault("orig", original) or o)
    cli.rebuild_with("apktool", "apktool", tmp_path / "root", out, apkeditor=None, original=orig)
    assert seen["orig"] == orig


def test_prepare_and_patcher_handle_new_config_and_concurrent_edits(tmp_path, monkeypatch, dex_bytes):
    from apk_surgeon import cli, patcher

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", dex_bytes(["a"]))
    root = tmp_path / "decoded"
    smali = root / "smali/com/google/firebase/analytics/FirebaseAnalytics.smali"
    smali.parent.mkdir(parents=True)
    smali.write_text(
        ".class public Lcom/google/firebase/analytics/FirebaseAnalytics;\n"
        ".method public logEvent(Ljava/lang/String;Landroid/os/Bundle;)V\n"
        "    .locals 1\n    const/4 v0, 0x1\n    return-void\n.end method\n"
        ".method public lock(Landroid/view/Window;)V\n"
        "    .locals 1\n    const/16 v0, 0x2000\n"
        "    invoke-virtual {p1, v0}, Landroid/view/Window;->addFlags(I)V\n    return-void\n.end method\n"
    )
    other = root / "smali/com/example/Other.smali"
    other.parent.mkdir(parents=True)
    other.write_text(
        ".class public Lcom/example/Other;\n"
        ".method public static keep()V\n    .locals 0\n    const/4 v0, 0x0\n    return-void\n.end method\n"
    )
    (root / "AndroidManifest.xml").write_text(
        f'<manifest xmlns:android="{ANDROID[1:-1]}" package="org.example"><application>'
        '<receiver android:name="com.google.android.gms.measurement.AppMeasurementReceiver"/>'
        "</application></manifest>"
    )
    recipe = recipes.load(write_recipe(tmp_path, "version: 1\nmethods:\n  - Lcom/example/Other;->keep()V\n"))
    monkeypatch.setattr(cli.engines, "decode_apktool", lambda *a, **k: engines.DecodeResult("apktool", root))
    args = SimpleNamespace(
        engine="apktool", sinkhole=False, allow_screenshots=True, trust_user_ca=True,
        strip_ad_permissions=False, disable_providers=False, smali_only=False,
    )
    result = cli.prepare(
        args, apk, tmp_path / "work", "apktool", apkeditor=None, recipe=recipe, notes=[], bypass=False,
    )
    changes = result["changes"]
    assert "Recipe: com.example.Other" in result["hits"]
    assert "return-void\n    const/4" in changes[smali]
    assert "const/16 v0, 0x0" in changes[smali]
    config = root / "res/xml/apk_surgeon_network_security_config.xml"
    assert config in changes and not config.exists()
    diff_text = "".join(patcher.diff(root, changes))
    assert "apk_surgeon_network_security_config.xml" in diff_text
    backup = tmp_path / "backup"
    patcher.apply(root, changes, backup)
    assert config.is_file()
    tree = parse_manifest(root / "AndroidManifest.xml")
    assert tree.getroot().find("application").get(ANDROID + "networkSecurityConfig") == (
        "@xml/apk_surgeon_network_security_config"
    )
    assert tree.xpath("//receiver")[0].get(ANDROID + "enabled") == "false"
