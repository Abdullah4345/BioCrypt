# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('data/theme_settings.csv', 'data'), ('data/encryption_keys.json', 'data'), ('data/file_names.json', 'data'), ('data/user_info.csv', 'data'), ('data/local_storage.txt', 'data'), ('data/vault', 'data/vault')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='BioCrypt-Personal-V0.4',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['resources/app_icon.icns'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='BioCrypt-Personal-V0.4',
)
app = BUNDLE(
    coll,
    name='BioCrypt-Personal-V0.4.app',
    icon='resources/app_icon.icns',
    bundle_identifier=None,
)
