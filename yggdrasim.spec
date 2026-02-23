block_cipher = None

a = Analysis(
    ['main/main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('LICENSE', '.'),
        ('SCP03/aid.txt', 'SCP03'),
        ('SCP03/fids.txt', 'SCP03'),
        ('SCP03/binds.json', 'SCP03'),
        ('SCP03/interface/binds.json', 'SCP03/interface'),
    ],
    hiddenimports=[
        'smartcard.System',
        'smartcard.CardConnection',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='YggdraSIM',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
