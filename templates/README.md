# Template File for VM Provision Scripts

File with extension "sh" for Linux VM, "ps1" for Windows VM.

## Workflow

Start main program: `python startrange.py`

Main steps:

1. Clear environment;
1. Generate scripts from templates;
1. Copy external dependencies;
1. Start vagrant VM; 
1. Run C2 commands;

