from pathlib import Path
import hashlib
import shutil
import datetime

source = Path.cwd() / 'outputs' / 'каскад'
destination = Path.home() / 'Desktop' / 'каскад'
assert source.is_dir() and (source / 'SHA256SUMS.txt').is_file()
destination.mkdir(exist_ok=True)
suffix = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')

def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()

count = 0
for path in source.rglob('*'):
    if not path.is_file():
        continue
    target = destination / path.relative_to(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise RuntimeError('Refusing to overwrite a symbolic link: ' + str(target))
    if target.exists() and digest(target) != digest(path):
        shutil.copy2(target, target.with_name(target.name + '.previous-' + suffix))
    shutil.copy2(path, target)
    assert digest(path) == digest(target), target
    count += 1

for line in (destination / 'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
    expected, relative = line.split('  ', 1)
    assert digest(destination / relative) == expected, relative
print('Desktop folder verified:', destination)
print('Copied and verified files:', count)
