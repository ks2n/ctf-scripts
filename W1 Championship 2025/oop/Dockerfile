# Dockerfile
FROM ubuntu:22.04 AS app
ARG DEBIAN_FRONTEND=noninteractive
ARG KEEP_FLAG=1
ENV TZ=UTC
ENV DEBIAN_FRONTEND=${DEBIAN_FRONTEND}

# --- System packages and python ---
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       locales \
       tzdata \
       build-essential \
       python3 \
       python3-dev \
       python3-pip \
       python3-venv \
       gdb \
       gdb-multiarch \
       git \
       curl \
       wget \
       netcat-openbsd \
       socat \
       vim \
       procps \
       pkg-config \
       libssl-dev \
       libffi-dev \
       libgmp-dev \
       unzip \
    && rm -rf /var/lib/apt/lists/*

# Ensure python3 and pip are default
RUN ln -sf /usr/bin/python3 /usr/bin/python \
    && python -m pip install --upgrade pip setuptools wheel

# --- Install pwntools and useful python libs ---
RUN pip install --no-cache-dir \
      pwntools \
      capstone \
      ropper \
      unicorn \
      keystone-engine || true

# --- Install pwndbg ---
# Clone pwndbg into /opt and run its setup script (it will pip-install its requirements)
RUN git clone --depth=1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && /opt/pwndbg/setup.sh --all || true

# --- Create user (with home) and workspace ---
RUN useradd -m -u 1000 -s /bin/bash user \
    && mkdir -p /home/user/work /home/user/.gdbinit.d \
    && chown -R user:user /home/user

# Copy the challenge binary (from build context)
COPY chall /home/user/chall
RUN chmod 555 /home/user/chall \
    && chown user:user /home/user/chall

# Optional flag file (toggle at build time with --build-arg KEEP_FLAG=0)
RUN if [ "${KEEP_FLAG}" = "1" ] ; then echo "W1{example_flag_GLHF}" > /flag.txt ; fi \
    && chmod 444 /flag.txt || true

WORKDIR /home/user

# Expose the service port
EXPOSE 9634/tcp

# Keep environment sane for pwndbg/gdb when connecting as root vs user
ENV HOME=/home/user

# Default command: run socat to serve the binary (same as your original)
# We run as user (safer), but socat needs permission; running as user is fine here.
USER user
CMD socat TCP-LISTEN:9634,reuseaddr,fork EXEC:"/home/user/chall"
