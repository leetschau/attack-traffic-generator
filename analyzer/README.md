# Packet Analyzer

```sh
podman build . -t auto-attack
podman run --rm -it -v .:/app auto-attack run scapy  # run scapy REPL
podman run --rm -it -v .:/app auto-attack run ipython
podman run --rm -it -v .:/app --entrypoint bash auto-attack  # run shell inside container
```
