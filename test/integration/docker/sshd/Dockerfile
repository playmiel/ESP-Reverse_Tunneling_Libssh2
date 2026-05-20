FROM alpine:3.19

RUN apk add --no-cache openssh-server bash && \
    ssh-keygen -A && \
    adduser -D -s /bin/bash testuser && \
    echo 'testuser:testpass' | chpasswd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22 22080 22081 22082

CMD ["/usr/sbin/sshd", "-D", "-e"]
