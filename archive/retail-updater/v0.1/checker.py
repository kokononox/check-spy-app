"""Read-only EU Retail version checker. No install/update engine."""
import json, re, ssl, threading, urllib.request
from datetime import datetime, timezone
from pathlib import Path

URL = 'https://eu.version.battle.net/v2/products/wow/versions'
LIMIT = 262144

def table(text):
    lines = [x.strip() for x in text.lstrip('\ufeff').splitlines() if x.strip() and not x.startswith('#')]
    if len(lines) < 2:
        raise ValueError('Version information is empty or malformed.')
    names = [x.split('!')[0] for x in lines[0].split('|')]
    if len(set(names)) != len(names):
        raise ValueError('Duplicate column names.')
    rows = []
    for line in lines[1:]:
        fields = line.split('|')
        if len(fields) != len(names):
            raise ValueError('Invalid version table row.')
        rows.append(dict(zip(names, fields)))
    return rows

def unique(rows):
    if len(rows) != 1:
        raise ValueError('Expected exactly one active Windows EU Retail installation/version.')
    return rows[0]

def valid(version, build):
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', version) or not re.fullmatch(r'[0-9a-fA-F]{32}', build):
        raise ValueError('Invalid version/build identifier.')
    return tuple(map(int, version.split('.')))

def compare(local_text, remote_text):
    local = unique([r for r in table(local_text) if r.get('Active') == '1' and r.get('Product') == 'wow' and r.get('Branch') == 'eu' and 'Windows' in r.get('Tags', '') and 'x86_64' in r.get('Tags', '')])
    remote = unique([r for r in table(remote_text) if r.get('Region') == 'eu'])
    lv = valid(local['Version'], local['Build Key'])
    rv = valid(remote['VersionsName'], remote['BuildConfig'])
    if str(rv[-1]) != remote.get('BuildId'):
        raise ValueError('Remote version and build number disagree.')
    if lv == rv and local['Build Key'].lower() == remote['BuildConfig'].lower():
        status = 'same_build'
    elif rv > lv:
        status = 'newer_eu_build_published'
    else:
        status = 'build_mismatch_needs_review'
    return {'tool': 'WoW Retail Version Check 0.1', 'mode': 'read_only_no_updater',
            'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'product': 'wow', 'region': 'eu',
            'local_version': local['Version'], 'remote_version': remote['VersionsName'],
            'local_build_config': local['Build Key'], 'remote_build_config': remote['BuildConfig'],
            'cdn_config_changed': local.get('CDN Key', '').lower() != remote.get('CDNConfig', '').lower(),
            'status': status, 'source': URL,
            'limitations': ['Installation contents not verified.', 'Realm compatibility not independently verified.', 'No game downloads or installation changes.', 'TACTSharp is not bundled or integrated in this version.']}

class StrictRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirect refused. Official version endpoint changed; review required.')

def fetch():
    opener = urllib.request.build_opener(StrictRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(URL, headers={'User-Agent': 'WoW-Retail-Version-Check/0.1', 'Cache-Control': 'no-cache'})
    with opener.open(request, timeout=25) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError('Version response exceeded safety limit.')
    return data.decode('utf-8-sig')

def main():
    import tkinter as tk
    from tkinter import filedialog, messagebox
    root = tk.Tk(); root.title('WoW Retail EU — Version Check 0.1'); root.geometry('650x410')
    tk.Label(root, text='فقط بررسی نسخه؛ این برنامه بازی را آپدیت نمی‌کند.', font=('Arial', 13)).pack(pady=12)
    tk.Label(root, text='Retail / EU / Windows x64 — No administrator access needed').pack()
    output = tk.Text(root, height=12, wrap='word'); output.pack(padx=15, pady=12, fill='both', expand=True)
    def show(text):
        output.delete('1.0', 'end'); output.insert('end', text)
    def run():
        name = filedialog.askopenfilename(title='Select .build.info in the WoW installation root', filetypes=[('Build info', '.build.info'), ('All files', '*')])
        if not name: return
        source = Path(name)
        if source.name != '.build.info':
            messagebox.showerror('Wrong file', 'Select the exact .build.info file.'); return
        button.config(state='disabled'); show('Checking official EU version…\nNo game files will be changed.')
        def worker():
            try:
                if source.stat().st_size > LIMIT: raise ValueError('Local metadata exceeded safety limit.')
                report = compare(source.read_text(encoding='utf-8-sig'), fetch())
                root.after(0, lambda: success(report, source.parent))
            except Exception as exc:
                # Do not expose local paths/account tags in shareable output.
                root.after(0, lambda kind=type(exc).__name__: failure(kind))
        threading.Thread(target=worker, daemon=True).start()
    def failure(kind):
        show('Check failed: ' + kind + '\nNo conclusion about updates. No game files changed.\nCheck Internet/DNS access and that this is an EU Windows Retail installation.'); button.config(state='normal')
    def success(report, installation):
        labels = {'same_build': 'نسخه و شناسهٔ ساخت برابر است؛ سلامت فایل‌ها بررسی نشده.',
                  'newer_eu_build_published': 'نسخهٔ جدید اروپا منتشر شده؛ آپدیت انجام نشده است.',
                  'build_mismatch_needs_review': 'اختلاف ساخت نیاز به بررسی دارد؛ چیزی جایگزین نکنید.'}
        show('Installed: ' + report['local_version'] + '\nPublished EU: ' + report['remote_version'] + '\n\n' + labels[report['status']] + '\n\nOnly version metadata checked. No TACTSharp integration yet.')
        button.config(state='normal')
        if not messagebox.askyesno('Report', 'Save a shareable report? No local paths, account tags, or keys are included.'): return
        target = filedialog.asksaveasfilename(title='Save OUTSIDE your game installation', initialfile='Retail-Version-to-share.json', defaultextension='.json', filetypes=[('JSON', '*.json')])
        if not target: return
        dest = Path(target).resolve()
        if dest.is_relative_to(installation.resolve()):
            messagebox.showerror('Not saved', 'Report must be saved outside the game installation.'); return
        try:
            dest.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        except OSError:
            messagebox.showerror('Not saved', 'Could not save report.')
    button = tk.Button(root, text='انتخاب .build.info و بررسی نسخه', command=run); button.pack(pady=10)
    root.mainloop()

if __name__ == '__main__': main()
