import json
import os
import shutil
import subprocess
import zipfile
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from apk_surgeon import llm, signing
from apk_surgeon.patcher import patch_smali, plan
from apk_surgeon.scanner import ANDROID, exodus


@pytest.mark.skipif(shutil.which("keytool") is None, reason="keytool from a JDK is not installed")
def test_persistent_key(tmp_path,monkeypatch):
    monkeypatch.setenv("HOME",str(tmp_path))
    monkeypatch.setenv("USERPROFILE",str(tmp_path))
    args = SimpleNamespace(keystore=None,ks_alias=None,ks_pass=None)
    key, alias, env = signing.identity(args)
    first = key.read_bytes()
    key2, _, env2 = signing.identity(args)
    assert key2.read_bytes() == first and env2["KS_SECRET"] == env["KS_SECRET"]
    if os.name != "nt":
        assert key.stat().st_mode & 0o777 == 0o600


def test_old_zipalign(tmp_path,monkeypatch):
    dest = tmp_path/"aligned.apk"
    with zipfile.ZipFile(dest,"w") as archive:
        archive.writestr("unused",b"")
    run = Mock(side_effect=[SimpleNamespace(returncode=1,stderr="invalid option -- P",stdout=""),None])
    monkeypatch.setattr(subprocess,"run",run)
    signing.align(tmp_path/"in.apk",dest)
    assert run.call_args_list[0].args[0][1:3] == ["-P","16"]
    assert run.call_args_list[1].args[0][1:3] == ["-p","-f"]


def test_providers_permissions(tmp_path):
    manifest = tmp_path/"AndroidManifest.xml"
    manifest.write_text(f'<manifest xmlns:android="{ANDROID[1:-1]}"><uses-permission android:name="com.google.android.gms.permission.AD_ID"/><application><provider android:name="io.sentry.android.core.SentryInitProvider"/><provider android:name="androidx.startup.InitializationProvider"/></application></manifest>')
    assert not plan(tmp_path,{})
    new = plan(tmp_path,{},True,True)[manifest]
    assert "AD_ID" not in new and new.count('android:enabled="false"') == 1


def test_local_ai_candidate(tmp_path,monkeypatch):
    path = tmp_path/"smali/a.smali"
    path.parent.mkdir()
    source = '.class public La;\n.method static a()V\n    .locals 1\n    const-string v0, "/analytics"\n    return-void\n.end method'
    path.write_text(source)
    payload = dict(method_name="a()V",reason="analytics",risk_level="low",safe_to_noop=True)
    import io
    opener = Mock()
    opener.open.return_value = io.BytesIO(json.dumps({"choices":[{"message":{"content":json.dumps(payload)}}]}).encode())
    monkeypatch.setattr(llm.urllib.request,"build_opener",lambda *a: opener)
    [(candidate,result)] = llm.analyze(tmp_path,"http://localhost:11434/v1","test")
    assert candidate == path
    assert patch_smali(source,{result["method_name"]}) != source
    for broken in (source.replace(".locals 1",".locals bad"),source.replace("a()V","a()I")):
        assert patch_smali(broken,{"a()V","a()I"}) == broken
    db = tmp_path/"trackers.json"
    db.write_text(json.dumps({"trackers":{"1":{"name":"test","code_signature":"^a$"}}}))
    assert exodus(tmp_path,db) == ["test"]
