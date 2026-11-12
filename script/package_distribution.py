from pathlib import Path
import hashlib
import html.parser
import runpy
import shutil
import urllib.parse
import zipfile

project = Path.cwd()
bundle = project / 'outputs' / 'каскад'
setup = project / 'work/windows/publish/setup/Cascade-Setup.exe'
app = project / 'work/windows/publish/app'
assert setup.exists() and (app / 'Cascade.exe').exists()
shutil.copyfile(setup, bundle / 'Windows/Cascade-Setup-x64.exe')
with zipfile.ZipFile(bundle / 'Windows/Cascade-Portable-x64.zip', 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for path in app.rglob('*'):
        if path.is_file():
            archive.write(path, path.relative_to(app))

with zipfile.ZipFile(bundle / 'Исходники/Cascade-source.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
    for directory in ['Sources', 'Tests', 'script', 'design', 'windows']:
        for path in (project / directory).rglob('*'):
            if not path.is_file() or any(part in ('bin', 'obj', 'publish', '.DS_Store', '__pycache__') for part in path.relative_to(project).parts):
                continue
            if path.name in ('payload.zip', 'payload.sha256'):
                continue
            archive.write(path, Path('Cascade-source') / path.relative_to(project))
    for name in ['Package.swift', '.gitignore']:
        archive.write(project / name, 'Cascade-source/' + name)
    archive.write(project / 'outputs/README-RU.md', 'Cascade-source/README-Mac.md')
    archive.write(bundle / 'ПРОВЕРКА.txt', 'Cascade-source/ПРОВЕРКА.txt')

runpy.run_path('script/package_guides.py', run_name='__main__')

class Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
    def handle_starttag(self, tag, attributes):
        self.urls.extend(value for key, value in attributes if key in ('href', 'src'))

for page in bundle.rglob('*.html'):
    parser = Links()
    parser.feed(page.read_text(encoding='utf-8'))
    for url in parser.urls:
        if url == 'SHA256SUMS.txt' or urllib.parse.urlparse(url).scheme or url.startswith('#'):
            continue
        assert (page.parent / urllib.parse.unquote(url)).exists(), (page, url)

def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()

files = sorted(p for p in bundle.rglob('*') if p.is_file() and p.name != 'SHA256SUMS.txt')
(bundle / 'SHA256SUMS.txt').write_text(''.join(digest(p) + '  ' + p.relative_to(bundle).as_posix() + '\n' for p in files), encoding='utf-8')
for path in bundle.rglob('*.zip'):
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None, path

output = project / 'outputs/каскад-комплект-0.3.0.zip'
temporary = output.with_suffix('.zip.tmp')
with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for path in bundle.rglob('*'):
        if path.is_file():
            archive.write(path, Path('каскад') / path.relative_to(bundle))
temporary.replace(output)
output.with_suffix('.sha256').write_text(digest(output) + '  ' + output.name + '\n', encoding='utf-8')
print(f'Bundle: {len(files) + 1} files, {sum(p.stat().st_size for p in bundle.rglob("*") if p.is_file()) / 1048576:.1f} MiB')
print(f'Archive: {output.name}, {output.stat().st_size / 1048576:.1f} MiB')
