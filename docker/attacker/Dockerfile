FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hping3 \
    hydra \
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

# HTTP path wordlist for fuzzing demo
RUN printf 'admin\nlogin\nbackup\nphpmyadmin\nwp-admin\napi\nconfig\n.env\ntest\nstaging\ndebug\nshell\nupload\ncgi-bin\n.git\npasswd\nshadow\nsecrets\nkeys\ntoken\n' \
    > /wordlist.txt

# SSH password wordlist — correct password (s3ntinel_brute) is at position 11
# so hydra makes ≥10 failed attempts before succeeding → fills ssh_flows window
RUN printf 'password\n123456\nadmin\ntoor\nroot\nletmein\npassword123\nqwerty\n12345678\nwelcome\nmaster\ns3ntinel_brute\n' \
    > /wordlist_ssh.txt

WORKDIR /scripts

CMD ["/bin/bash"]
