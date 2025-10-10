# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for SysHardn

Usage:
    pyinstaller syshardn.spec

This will create a standalone executable in the dist/ directory.
"""

import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files

block_cipher = None
project_root = os.path.abspath(os.getcwd())


click_datas, click_binaries, click_hiddenimports = collect_all('click')
rich_datas, rich_binaries, rich_hiddenimports = collect_all('rich')
yaml_datas, yaml_binaries, yaml_hiddenimports = collect_all('yaml')
jinja2_datas, jinja2_binaries, jinja2_hiddenimports = collect_all('jinja2')
reportlab_datas, reportlab_binaries, reportlab_hiddenimports = collect_all('reportlab')

datas = [
    # Rules directory (critical!)
    ('rules', 'rules'),
    # Any templates for reports
    ('src/syshardn/reporters/templates', 'syshardn/reporters/templates') if os.path.exists('src/syshardn/reporters/templates') else None,
]

datas = [d for d in datas if d is not None]

# Add collected data files
datas.extend(click_datas)
datas.extend(rich_datas)
datas.extend(yaml_datas)
datas.extend(jinja2_datas)
datas.extend(reportlab_datas)

binaries = []
binaries.extend(click_binaries)
binaries.extend(rich_binaries)
binaries.extend(yaml_binaries)
binaries.extend(jinja2_binaries)
binaries.extend(reportlab_binaries)


excluded_libs = [
    'libstdc++', 'libgcc_s', 'libgomp', 'libgfortran',
    'libz.so', 'libc.so', 'libm.so', 'libpthread', 'libdl',
    'librt.so', 'libresolv', 'libnss', 'libutil.so'
]
binaries = [
    (name, path, typ) for name, path, typ in binaries 
    if not any(excl in os.path.basename(name) for excl in excluded_libs)
]

hiddenimports = [
    'syshardn',
    'syshardn.cli',
    'syshardn.core',
    'syshardn.core.os_detector',
    'syshardn.parsers',
    'syshardn.parsers.rule_loader',
    'syshardn.executors',
    'syshardn.executors.base_executor',
    'syshardn.executors.executor_factory',
    'syshardn.executors.linux_executor',
    'syshardn.executors.windows_executor',
    'syshardn.reporters',
    'syshardn.reporters.report_generator',
    'syshardn.utils',
    'syshardn.utils.logger',
    'click',
    'yaml',
    'rich',
    'rich.console',
    'rich.table',
    'rich.progress',
    'rich.panel',
    'rich.syntax',
    'jinja2',
    'jinja2.ext',
    'dateutil',
    'reportlab',
    'reportlab.lib',
    'reportlab.lib.pagesizes',
    'reportlab.lib.styles',
    'reportlab.lib.units',
    'reportlab.lib.colors',
    'reportlab.platypus',
    'reportlab.platypus.paragraph',
    'reportlab.platypus.tables',
    'reportlab.platypus.doctemplate',
    'json',
    'pathlib',
    'subprocess',
    'platform',
]

hiddenimports.extend(click_hiddenimports)
hiddenimports.extend(rich_hiddenimports)
hiddenimports.extend(yaml_hiddenimports)
hiddenimports.extend(jinja2_hiddenimports)
hiddenimports.extend(reportlab_hiddenimports)

a = Analysis(
    ['src/syshardn/cli.py'],
    pathex=[project_root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'pytest',
        'pytest-cov',
        'black',
        'flake8',
        'mypy',
        'isort',
        'matplotlib',
        'tkinter',
        'test',
        'tests',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
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
    name='syshardn',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Console application (not GUI)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt' if os.path.exists('version_info.txt') else None,
    icon='icon.icns' if os.path.exists('icon.icns') else None,
)

