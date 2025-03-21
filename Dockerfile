FROM dorkamotorka/ubuntu-ebpf
RUN apt-get install -y git 

COPY . /home/src
WORKDIR /home/src
RUN go build -o /bin/action ./app

ENTRYPOINT [ "/bin/action" ]
