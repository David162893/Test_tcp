# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['tcp_test_service.py'],
    pathex=[],
    binaries=[('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/dhnetsdk.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/avnetsdk.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/dhconfigsdk.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/Infra.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/IvsDrawer.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/libeay32.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/ssleay32.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/play.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/RenderEngine.dll', '.'), ('C:/Users/drodriguez/Desktop/Proyectos/Dahua acces control/dahua/dahua_sdk/StreamConvertor.dll', '.')],
    datas=[('config/config.ini', 'config')],
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
    a.binaries,
    a.datas,
    [],
    name='tcp_test_service',
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
)
