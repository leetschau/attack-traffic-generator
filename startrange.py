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
output_dir = Path(kv['range_root'])

print(f'\nClear environment in folder {output_dir} ...\n')
if (output_dir / 'Vagrantfile').exists():
    run(['vagrant', 'destroy', '-f'], cwd=output_dir, check=True)
shutil.rmtree(output_dir, ignore_errors=True)
output_dir.mkdir()

print(f'\nGenerating scripts according to {args.conf} ...\n')
env = Environment(loader=FileSystemLoader(args.template_path))
for tf in Path(args.template_path).iterdir():
    if (tf.is_dir() or tf.suffix == '.md'):
        continue
    template = env.get_template(tf.name)
    outfile = output_dir / tf.name
    print(f'Generating script {outfile} based on {tf.name} ...')
    outfile.write_text(template.render(kv))

if not args.run:
    print(f'\nUp running the range with:\ncd {output_dir}\n./startrange')
    sys.exit(0)

print('\nBuilding range ...\n')
run(['vagrant', 'up'], cwd=output_dir, check=True)

print('\nExecuting C2 commands ...\n')
# vagrant ssh attacker -c 'tmux new-window -t collector -n commands "cd Cobaltstrike-4.4 && ./agscript 192.168.56.33 50050 black 456321 /vagrant/commands.cna"'
