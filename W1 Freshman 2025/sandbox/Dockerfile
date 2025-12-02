FROM ubuntu:24.04

RUN apt-get update && apt-get install socat -y netcat-openbsd adduser

RUN adduser --disabled-password --gecos "" user

WORKDIR /home/user

COPY ./jail ./jail
COPY ./sandbox ./chall
COPY ./flagriel.txt ./flag.txt
COPY ./flag.txt ./jail/flag.txt
COPY ./flagroot.txt /flag.txt
COPY ./flaghome.txt /home/flag.txt
RUN chmod 755 ./chall && \ 
    chown ubuntu:ubuntu ./flag.txt && \
    chown ubuntu:ubuntu /home/user && \ 
    chmod 755 ./flag.txt

WORKDIR /
USER root
EXPOSE 1337

ENTRYPOINT ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/user/chall"]
