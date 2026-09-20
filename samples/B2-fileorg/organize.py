import os, sys, shutil

d = sys.argv[1]
for f in os.listdir(d):
    p = os.path.join(d, f)
    if os.path.isfile(p):
        ext = os.path.splitext(f)[1].lstrip('.') or 'other'
        os.makedirs(os.path.join(d, ext), exist_ok=True)
        shutil.move(p, os.path.join(d, ext, f))
