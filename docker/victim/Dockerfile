FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Create a user with a weak password for brute-force demo
RUN useradd -m -s /bin/bash sentinel_user \
 && echo "sentinel_user:password123" | chpasswd \
 && echo "sentinel_user:admin" | chpasswd \
 && echo "root:toor" | chpasswd

# Allow root login and password auth (intentionally weak — demo only)
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && echo "MaxAuthTries 100" >> /etc/ssh/sshd_config

RUN mkdir -p /run/sshd

# Pipe auth.log to stdout so `docker logs victim` shows brute-force attempts
RUN ln -sf /dev/stdout /var/log/auth.log

EXPOSE 22

# sshd -e sends log output to stderr (visible in docker logs)
CMD ["/usr/sbin/sshd", "-D", "-e"]
