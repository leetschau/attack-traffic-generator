import sys
import yaml
import shutil
import argparse
from pathlib import Path
from subprocess import run
from jinja2 import Environment, FileSystemLoader

parser = argparse.ArgumentParser(description='Generate script from range configurations and templates')
parser.add_argument('-c', '--conf', default='range.yml', help='default: range.yml')
parser.add_argument('-t', '--template-path', default='./templates', help='default: ./templates')
parser.add_argument('-r', '--run', action='store_true', help='up runnning the range with `vagrant up`')
args = parser.parse_args()

kv = yaml.safe_load(Path(args.conf).read_text())
range_dir = Path(kv['range_root'])

print(f'\n\nClear environment in folder {range_dir} ...\n')
if (range_dir / 'Vagrantfile').exists():
    run(['vagrant', 'destroy', '-f'], cwd=range_dir, check=True)
shutil.rmtree(range_dir, ignore_errors=True)
range_dir.mkdir()

print(f'\n\nGenerating scripts according to {args.conf} ...\n')
env = Environment(loader=FileSystemLoader(args.template_path))
for tf in Path(args.template_path).iterdir():
    if (tf.is_dir() or tf.suffix == '.md'):
        continue
    template = env.get_template(tf.name)
    outfile = range_dir / tf.name
    print(f'Generating script {outfile} based on {tf.name} ...')
    outfile.write_text(template.render(kv))

dep_path = kv['dependencies']['path']
for fn in Path(dep_path).iterdir():
    print(f'Copy {fn.name} to {range_dir} ...')
    shutil.copy(fn, range_dir / fn.name)

if not args.run:
    print(f'\nUp running the range with:\ncd {range_dir}\n./startrange')
    sys.exit(0)

print('\n\nBuilding range ...\n')
run(['vagrant', 'up'], cwd=range_dir, check=True)

print('\n\nExecuting C2 commands ...\n')
run(['bash', 'c2commands.sh'], cwd=range_dir, check=True)
