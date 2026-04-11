FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hping3 \
    netcat-openbsd \
    curl \
    python3 \
    python3-pip \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# wfuzz for HTTP fuzzing
RUN pip3 install --no-cache-dir wfuzz

# Copy attack scripts
COPY docker/attacker/scripts/ /scripts/
RUN chmod +x /scripts/*.sh

# Minimal HTTP wordlist for fuzzing demo
RUN echo -e "admin\nlogin\nbackup\nphpmyadmin\nwp-admin\napi\nconfig\n.env\ntest\nstaging\ndebug\nshell\nupload\ncgi-bin\n.git\npasswd\nshadow\nsecrets\nkeys\ntoken" \
    > /wordlist.txt

WORKDIR /scripts

CMD ["/bin/bash"]
