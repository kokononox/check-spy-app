import pathlib,json,urllib.request,hashlib,zipfile
root=pathlib.Path(__file__).resolve().parents[1];rt=root/'runtime';rt.mkdir(exist_ok=True)
for entry in json.loads((root/'DEPENDENCIES.json').read_text()):
 blob=urllib.request.urlopen(entry['Source'],timeout=120).read();assert hashlib.sha256(blob).hexdigest()==entry['SHA256']
 tmp=root/entry['File'];tmp.write_bytes(blob)
 with zipfile.ZipFile(tmp) as z:z.extractall(rt)
 tmp.unlink()
(rt/'python312._pth').write_text('python312.zip\n.\n..\nimport site\n')
print('Portable dependencies verified against package hashes.')
