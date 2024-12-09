# Use Kali Linux as the base image
FROM kalilinux/kali-rolling

# Install necessary tools
RUN apt-get update && \
    apt-get install -y wget

RUN wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz && \
    tar -xvf go1.23.4.linux-amd64.tar.gz

RUN rm go1.23.4.linux-amd64.tar.gz

RUN ln -s /go/bin/go /usr/bin/go
RUN ln -s /go/bin/gofmt /usr/bin/gofmt

RUN apt-get install libpcap-dev -y

RUN apt-get install build-essential -y

RUN apt-get install net-tools -y

# Set the command to keep the container running
CMD ["tail", "-f", "/dev/null"]
