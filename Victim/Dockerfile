# Use Alpine Linux as the base image
FROM alpine:latest


RUN apk update && \
    apk add lftp

# Set the command to keep the container running
CMD ["tail", "-f", "/dev/null"]
