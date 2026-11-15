"""Read-only conversion of a BagIt 1.0 bag into the audit manifest format.

The bag is treated as static, trusted local input (the same trust boundary as
the default ``static`` capture mode).  Nothing inside the bag is ever written:
the result is a fresh ``{payload_root, entries}`` manifest published atomically
at a path outside the bag.

Validation is staged: bag metadata is parsed first, the bag tree is scanned
without following links, and only then are payload and tag bytes read.  Every
payload file is read exactly once and all declared digests are updated from the
same bytes, so a bag cannot present different content to the sha256 and sha512
manifests.  Only after the whole bag passes is the output manifest serialized
in memory (bounded by the audit limits) and atomically renamed into place; a
failure at any entry, including the last one, therefore leaves no half-product.

Standard library only.
"""
from pathlib import Path
import hashlib, json, os, re, stat, tempfile
from .files import relative
from .model import validate_entries

MAX_FILE=8_000_000
MAX_TAG_FILE=8_000_000
MAX_TOTAL=32_000_000
MAX_FILES=2000
MAX_PAYLOAD_ENTRIES=2000
MAX_ENTRIES=5000
MAX_TAG_ENTRIES=5000
CHUNK=65_536
ALGORITHMS={'sha256':hashlib.sha256,'sha512':hashlib.sha512}
HEX_LENGTH={'sha256':64,'sha512':128}
MANIFEST_NAME=re.compile(r'^(tagmanifest|manifest)-(.+)\.txt$')


class BagError(ValueError):
    """A BagIt contract violation, unsafe entry or failed verification."""


def _lines(raw,label):
    """Decode a tag file as strict UTF-8 and yield (line number, text)."""
    try:text=raw.decode('utf-8')
    except UnicodeDecodeError:
        raise BagError(label+': not valid UTF-8')
    lines=text.split('\n')
    if lines and not lines[-1]:lines.pop()
    result=[]
    for number,line in enumerate(lines,1):
        if line.endswith('\r'):line=line[:-1]
        if not line:raise BagError('%s:%d: blank line'%(label,number))
        result.append((number,line))
    return result


def _read_bytes(path,label,limit=None):
    """Read a root tag file without following a last-moment symlink."""
    limit=MAX_TAG_FILE if limit is None else limit
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
    try:descriptor=os.open(os.fspath(path),flags)
    except OSError as e:
        raise BagError('%s: cannot read file: %s'%(label,e.strerror or e))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BagError(label+': not a regular file')
        raw=b''
        while len(raw)<=limit:
            try:chunk=os.read(descriptor,CHUNK)
            except OSError as e:raise BagError('%s: read failed: %s'%(label,e.strerror or e))
            if not chunk:break
            raw+=chunk
    finally:os.close(descriptor)
    if len(raw)>limit:raise BagError(label+': file exceeds 8 MB limit')
    return raw


def _parse_bagit(bag,files):
    """Validate bagit.txt: exactly the two BagIt 1.0 UTF-8 declarations."""
    label='bagit.txt'
    if label not in files:raise BagError('bagit.txt: missing required bag metadata file')
    lines=_lines(_read_bytes(bag/label,label),label)
    fields={}
    for number,line in lines:
        if ':' not in line:raise BagError('bagit.txt:%d: expected "Key: value"'%number)
        key,value=line.split(':',1);key=key.strip();value=value.strip()
        name=key.lower()
        if name not in ('bagit-version','tag-file-character-encoding'):
            raise BagError('bagit.txt:%d: unexpected field: %s'%(number,key))
        if name in fields:raise BagError('bagit.txt:%d: duplicate field: %s'%(number,key))
        fields[name]=(value,number)
    if 'bagit-version' not in fields:raise BagError('bagit.txt: missing BagIt-Version')
    if 'tag-file-character-encoding' not in fields:
        raise BagError('bagit.txt: missing Tag-File-Character-Encoding')
    version,line=fields['bagit-version']
    if version!='1.0':raise BagError('bagit.txt:%d: unsupported BagIt-Version: %s'%(line,version))
    encoding,line=fields['tag-file-character-encoding']
    if encoding.lower()!='utf-8':
        raise BagError('bagit.txt:%d: unsupported Tag-File-Character-Encoding: %s'%(line,encoding))
    if len(lines)!=2:
        raise BagError('bagit.txt:%d: unexpected extra field: %s'%(lines[2][0],lines[2][1]))
    return version


def _manifest_names(files):
    """Find root manifest/tagmanifest files; reject unsupported algorithms."""
    payload={};tags={}
    for name in sorted(files):
        if '/' in name:continue
        match=MANIFEST_NAME.match(name)
        if not match:continue
        kind,algorithm=match.groups();algorithm=algorithm.lower()
        if algorithm not in ALGORITHMS:
            raise BagError('%s: unsupported manifest algorithm: %s'
                           %(name,algorithm or '<empty>'))
        target=payload if kind=='manifest' else tags
        if algorithm in target:
            raise BagError('%s: duplicate %s algorithm: %s'%(name,kind,algorithm))
        target[algorithm]=name
    if not payload:
        raise BagError('bag root: no supported payload manifest '
                       '(manifest-sha256.txt or manifest-sha512.txt)')
    return payload,tags


def _parse_manifest(bag,label,kind,algorithm,limit):
    """Parse one manifest into {relative path: {digest, line}}.

    Paths are canonical relative POSIX strings; payload manifests may only name
    files under data/ and tag manifests may not name payload files.  A tag
    manifest may list another tag manifest but never itself (its own digest
    cannot be known).  Duplicates within a single file are rejected.
    """
    entries={}
    for number,line in _lines(_read_bytes(bag/label,label),label):
        parts=line.split(None,1)
        if len(parts)!=2:
            raise BagError('%s:%d: expected "<digest>  <path>"'%(label,number))
        digest,name=parts
        pattern='[0-9a-f]{%d}'%HEX_LENGTH[algorithm]
        if not re.fullmatch(pattern,digest):
            raise BagError('%s:%d: expected a lowercase %s digest (%d hex characters)'
                           %(label,number,algorithm,HEX_LENGTH[algorithm]))
        try:relative(name)
        except ValueError as e:raise BagError('%s:%d: invalid path: %s'%(label,number,e))
        if kind=='payload':
            if not name.startswith('data/'):
                raise BagError('%s:%d: payload path must be under data/: %s'
                               %(label,number,name))
        else:
            if name=='data' or name.startswith('data/'):
                raise BagError('%s:%d: tag manifest lists payload path: %s'
                               %(label,number,name))
            if name==label:
                raise BagError('%s:%d: tag manifest must not list itself: %s'
                               %(label,number,name))
        if name in entries:
            raise BagError('%s:%d: duplicate path: %s'%(label,number,name))
        if len(entries)>=limit:
            raise BagError('%s:%d: entry limit (%d) exceeded'%(label,number,limit))
        entries[name]={'digest':digest,'line':number}
    return entries


def _scan(bag):
    """Inventory the bag without following links; reject any link or special file."""
    files={};directories=set();count=0
    stack=[((),bag)]
    while stack:
        parts,directory=stack.pop()
        try:
            with os.scandir(directory) as stream:names=sorted(entry.name for entry in stream)
        except OSError as e:
            label='/'.join(parts) or '.'
            raise BagError('%s: cannot scan directory: %s'%(label,e.strerror or e))
        pending=[]
        for name in names:
            count+=1
            if count>MAX_ENTRIES:raise BagError('bag: inventory exceeds 5000 entries')
            path=directory/name;label='/'.join(parts+(name,))
            try:info=path.lstat()
            except OSError as e:raise BagError('%s: cannot inspect entry: %s'
                                               %(label,e.strerror or e))
            if stat.S_ISLNK(info.st_mode):
                raise BagError(label+': symbolic link is not allowed')
            if stat.S_ISDIR(info.st_mode):
                directories.add(label);pending.append((parts+(name,),path))
            elif stat.S_ISREG(info.st_mode):files[label]=info.st_size
            else:raise BagError(label+': not a regular file or directory')
        for item in reversed(pending):stack.append(item)
    return files,directories


def _parse_oxum(bag,files):
    """Return (bytes, files, line) from bag-info.txt, or None when absent."""
    label='bag-info.txt'
    if label not in files:return None
    found=None
    for number,line in _lines(_read_bytes(bag/label,label),label):
        if ':' not in line:continue
        key,value=line.split(':',1)
        if key.strip().lower()!='payload-oxum':continue
        if found is not None:
            raise BagError('bag-info.txt:%d: duplicate Payload-Oxum'%number)
        match=re.fullmatch(r'([0-9]+)\.([0-9]+)',value.strip())
        if not match:
            raise BagError('bag-info.txt:%d: malformed Payload-Oxum: %s'%(number,value.strip()))
        found=(int(match.group(1)),int(match.group(2)),number)
    return found


def _hash_file(path,label,algorithms,limit=None):
    """Read one regular file once and return (byte count, algorithm digests)."""
    limit=MAX_FILE if limit is None else limit
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)
    try:descriptor=os.open(os.fspath(path),flags)
    except OSError as e:raise BagError('%s: cannot open file: %s'%(label,e.strerror or e))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BagError(label+': not a regular file')
        digests={name:ALGORITHMS[name]() for name in algorithms};count=0
        while True:
            try:chunk=os.read(descriptor,CHUNK)
            except OSError as e:
                raise BagError('%s: read failed: %s'%(label,e.strerror or e))
            if not chunk:break
            count+=len(chunk)
            if count>limit:raise BagError(label+': file exceeds 8 MB limit')
            for digest in digests.values():digest.update(chunk)
        if os.fstat(descriptor).st_size!=count:
            raise BagError(label+': file changed while reading')
    finally:os.close(descriptor)
    return count,{name:digest.hexdigest() for name,digest in digests.items()}


def _check_output(bag,destination):
    """The output must be a plain file path outside the bag tree."""
    target=destination.resolve()
    if target==bag or bag in target.parents:
        raise BagError('output manifest must stay outside the bag')
    if destination.is_symlink():raise BagError('output manifest cannot be a symlink')
    if destination.exists() and destination.is_dir():
        raise BagError('output manifest must be a file path, not a directory')


def _publish(destination,raw):
    """Atomically replace the destination with the prepared manifest bytes."""
    destination.parent.mkdir(parents=True,exist_ok=True)
    if destination.is_symlink():raise BagError('output manifest cannot be a symlink')
    descriptor,temporary=tempfile.mkstemp(dir=str(destination.parent),
                                           prefix=destination.name+'.',suffix='.tmp')
    try:
        with os.fdopen(descriptor,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,destination)
        try:
            directory=os.open(str(destination.parent),os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        except OSError:
            directory=None
        if directory is not None:
            try:os.fsync(directory)
            except OSError:pass
            finally:os.close(directory)
    finally:
        if os.path.exists(temporary):
            try:os.unlink(temporary)
            except OSError:pass


def import_bag(bag,output):
    """Convert a BagIt 1.0 bag into an audit manifest; return a summary.

    Raises :class:`BagError` (a ``ValueError``) on any contract violation, with
    the offending tag file and line where one exists.  The destination is only
    touched after every check has passed.
    """
    bag=Path(bag)
    try:root_mode=bag.lstat().st_mode
    except OSError:raise BagError('bag: not an existing directory')
    if stat.S_ISLNK(root_mode):raise BagError('bag: cannot be a symbolic link')
    if not stat.S_ISDIR(root_mode):raise BagError('bag: not a directory')
    bag=bag.resolve()
    destination=Path(output)
    _check_output(bag,destination)

    files,directories=_scan(bag)
    if 'data' not in directories:raise BagError('bag: missing data/ payload directory')
    payload={name:size for name,size in files.items() if name.startswith('data/')}
    tags={name:size for name,size in files.items() if not name.startswith('data/')}
    if len(payload)>MAX_FILES:
        raise BagError('data/: payload file limit (%d) exceeded'%MAX_FILES)

    version=_parse_bagit(bag,files)
    payload_manifests,tag_manifests=_manifest_names(files)
    expected_payload={algorithm:_parse_manifest(bag,label,'payload',algorithm,
                                                MAX_PAYLOAD_ENTRIES)
                      for algorithm,label in sorted(payload_manifests.items())}
    actual=set(payload)
    for algorithm,label in sorted(payload_manifests.items()):
        expected=expected_payload[algorithm]
        absent=sorted(name for name in expected if name not in actual)
        if absent:
            name=absent[0]
            raise BagError('%s:%d: listed payload file is missing: %s'
                           %(label,expected[name]['line'],name))
        unlisted=sorted(name for name in actual if name not in expected)
        if unlisted:
            raise BagError('%s: payload file is not listed in %s'%(unlisted[0],label))
    oxum=_parse_oxum(bag,tags)

    algorithms=sorted(set(payload_manifests)|{'sha256'})
    entries=[];total=0
    for name,before in sorted(payload.items()):
        count,digests=_hash_file(bag/name,name,algorithms)
        if count!=before:raise BagError(name+': file changed while reading')
        total+=count
        if total>MAX_TOTAL:raise BagError('data/: payload total exceeds 32 MB limit')
        for algorithm,label in sorted(payload_manifests.items()):
            expected=expected_payload[algorithm][name]
            if digests[algorithm]!=expected['digest']:
                raise BagError('%s:%d: digest mismatch for %s (%s)'
                               %(label,expected['line'],name,algorithm))
        # Bag manifest paths are relative to the bag root; the audit manifest
        # addresses payload files relative to its own payload_root ("data").
        entries.append({'path':name[len('data/'):],'bytes':count,
                        'sha256':digests['sha256']})

    if oxum:
        expected_bytes,expected_files,line=oxum
        if expected_files!=len(payload):
            raise BagError('bag-info.txt:%d: Payload-Oxum file count %d != %d'
                           %(line,expected_files,len(payload)))
        if expected_bytes!=total:
            raise BagError('bag-info.txt:%d: Payload-Oxum byte count %d != %d'
                           %(line,expected_bytes,total))

    required_tags=set(tags)-set(tag_manifests.values())
    expected_tags={algorithm:_parse_manifest(bag,label,'tag',algorithm,MAX_TAG_ENTRIES)
                   for algorithm,label in sorted(tag_manifests.items())}
    for algorithm,label in sorted(tag_manifests.items()):
        expected=expected_tags[algorithm]
        absent=sorted(name for name in expected if name not in tags)
        if absent:
            name=absent[0]
            raise BagError('%s:%d: listed tag file is missing: %s'
                           %(label,expected[name]['line'],name))
        uncovered=sorted(required_tags-set(expected))
        if uncovered:
            raise BagError('%s: required tag file is not listed: %s'
                           %(label,uncovered[0]))
    if tag_manifests:
        # Every declared tag digest is verified, including a tag manifest that
        # cross-lists another tag manifest.  Coverage is still required only
        # for non-payload, non-tagmanifest tag files.
        listed_tags=set().union(*(set(entries) for entries in expected_tags.values()))
        tag_bytes=0
        for name in sorted(listed_tags):
            count,digests=_hash_file(bag/name,name,sorted(tag_manifests),MAX_TAG_FILE)
            if count!=tags[name]:raise BagError(name+': file changed while reading')
            tag_bytes+=count
            if tag_bytes>MAX_TOTAL:raise BagError('tag files: total exceeds 32 MB limit')
            for algorithm,label in sorted(tag_manifests.items()):
                expected=expected_tags[algorithm].get(name)
                if expected is not None and digests[algorithm]!=expected['digest']:
                    raise BagError('%s:%d: digest mismatch for %s (%s)'
                                   %(label,expected['line'],name,algorithm))

    manifest={'payload_root':'data','entries':entries}
    try:validate_entries(manifest)
    except ValueError as e:raise BagError('generated manifest violates audit contract: %s'%e)
    raw=(json.dumps(manifest,sort_keys=True,ensure_ascii=False,allow_nan=False,
                    indent=2)+'\n').encode('utf-8')
    checksum=hashlib.sha256(raw).hexdigest()
    _publish(destination,raw)
    return {'schema_version':1,'manifest':str(destination.resolve()),
            'manifest_sha256':checksum,'manifest_bytes':len(raw),
            'bagit_version':version,'payload_root':'data',
            'algorithms':sorted(payload_manifests),
            'tag_algorithms':sorted(tag_manifests),
            'payload_files':len(entries),'payload_bytes':total,
            'payload_oxum':('%d.%d'%(oxum[0],oxum[1]) if oxum else None),
            'tag_files':len(required_tags)}
