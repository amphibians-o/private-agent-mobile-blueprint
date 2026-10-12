"""Read-only, current-tree public bundle checks. Not a security certification."""
import argparse, hashlib, json, os, posixpath, re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

RULES={
    'network-address':r'(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])',
    'ipv6-address':r'\b(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]{1,}\b',
    'absolute-path':r'(?i)(?<!\w)(?:[a-z]:[\\/]|\\\\[A-Za-z0-9][A-Za-z0-9._-]*\\[A-Za-z0-9]|/(?:home|Users|mnt)/)',
    'private-hostname':r'(?i)\b[\w.-]+\.ts\.net\b',
    'private-key':r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
    'credential-url':r'(?i)[?&](?:token|key|api_key|csrf|code|password|secret)=[^\s&]+',
    'github-token':r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b',
    'bearer-value':r'(?i)\bBearer\s+[A-Za-z0-9._~-]{20,}',
    'email-address':r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
}

def linked(path):
    return path.is_symlink() or bool(getattr(path,'is_junction',lambda:False)())

def audit(root):
    findings=[];hashes={};count=0
    def flag(file,rule,line=None):
        item={'file':file,'rule':rule}
        if line is not None:item['line']=line
        findings.append(item)
    def report():return {'files_checked':count,'findings':findings,'sha256':hashes,'git_history_checked':False}
    if linked(root):flag('.','linked-root');return report()
    try:
        manifest_path=root/'upload-manifest.json'
        if linked(manifest_path):raise ValueError('linked manifest')
        manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
        files=manifest['files']
        if not isinstance(files,list) or not files or any(not isinstance(n,str) for n in files):raise ValueError('invalid files')
        if len(set(files))!=len(files):raise ValueError('duplicate files')
        for name in files:
            p=PurePosixPath(name)
            if p.is_absolute() or '..' in p.parts or '\\' in name or p.as_posix()!=name:raise ValueError('unsafe name')
            if not re.fullmatch(r'[A-Za-z0-9_.\-/]+',name) or '.git' in p.parts:raise ValueError('unsafe name')
        if 'upload-manifest.json' not in files:raise ValueError('manifest not included')
    except (OSError,UnicodeError,ValueError,KeyError,TypeError):
        flag('upload-manifest.json','invalid-manifest');return report()
    actual=set();blocked=set()
    def walk_error(_):flag('.','unreadable-tree')
    for parent,dirs,names in os.walk(root,followlinks=False,onerror=walk_error):
        parent=Path(parent)
        for directory in list(dirs):
            path=parent/directory;rel=path.relative_to(root).as_posix()
            if rel=='.git':dirs.remove(directory);continue
            if linked(path):flag(rel,'linked-directory');blocked.add(rel);dirs.remove(directory)
        for name in names:
            path=parent/name;rel=path.relative_to(root).as_posix();actual.add(rel)
            if linked(path):flag(rel,'linked-file');blocked.add(rel)
    for name in sorted(actual-set(files)):flag(name,'unlisted-file')
    for name in sorted(set(files)-actual):flag(name,'missing-file')
    for name in files:
        path=root/name
        if name not in actual or name in blocked:continue
        mock_images={'examples/screenshots/list.png','examples/screenshots/chat.png','examples/screenshots/resources.png'}
        if name in mock_images:
            try:
                raw=path.read_bytes();digest=hashlib.sha256(raw).hexdigest()
                expected=manifest.get('reviewed_images',{}).get(name)
                if not raw.startswith(b'\x89PNG\r\n\x1a\n') or len(raw)>1000000:flag(name,'invalid-image');continue
                if not isinstance(expected,str) or digest!=expected:flag(name,'image-hash-mismatch');continue
                count+=1;hashes[name]=digest
            except (OSError,AttributeError):flag(name,'unreadable-image')
            continue
        if path.suffix not in ('.md','.py','.json') and name not in ('.gitignore','LICENSE','examples/phone-ui.html'):flag(name,'unsupported-type');continue
        try:
            raw=path.read_bytes()
            if len(raw)>1000000:flag(name,'oversize-file');continue
            if b'\x00' in raw:flag(name,'binary-file');continue
            text=raw.decode('utf-8')
        except (OSError,UnicodeError):flag(name,'unreadable-text');continue
        count+=1;hashes[name]=hashlib.sha256(raw).hexdigest()
        for rule,pattern in RULES.items():
            for match in re.finditer(pattern,text):flag(name,rule,text.count('\n',0,match.start())+1)
        if path.suffix=='.md':
            for match in re.finditer(r'\[[^\]\n]*\]\(([^)\s]+)\)',text):
                dest=unquote(match.group(1));parts=urlsplit(dest)
                if parts.scheme:
                    if parts.scheme!='https' or parts.username or parts.password:flag(name,'unsafe-link')
                    continue
                if dest.startswith('#'):continue
                local=posixpath.normpath((PurePosixPath(name).parent/PurePosixPath(parts.path)).as_posix())
                if local not in files:flag(name,'missing-local-link',text.count('\n',0,match.start())+1)
    return report()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    args=parser.parse_args()
    result=audit(args.root)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 1 if result['findings'] else 0
if __name__=='__main__':raise SystemExit(main())
