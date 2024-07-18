FROM python:3.12.4

WORKDIR /app

RUN apt-get update -y && apt-get install -y texlive tcpdump
RUN pip install --user -U pip && pip install --user poetry

ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin

ENTRYPOINT ["poetry"]
