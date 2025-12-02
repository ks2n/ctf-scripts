FROM ubuntu:24.04

RUN apt-get update && apt-get install socat -y netcat-openbsd adduser

RUN adduser --disabled-password --gecos "" user

WORKDIR /home/user

COPY ./flag.txt ./flag.txt
COPY ./mission_possible ./chall
RUN chmod 755 /home/user/chall

USER user

EXPOSE 1337

ENTRYPOINT ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'/home/user/chall'"]

