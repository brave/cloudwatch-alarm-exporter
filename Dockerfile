# iron/go is the alpine image with only ca-certificates added
FROM golang:1.12.7-alpine

WORKDIR /app

# Now just add the binary
ADD cloudwatch-alarm-exporter /app/

# Set up operating environment
USER nobody
ENV AWS_CONFIG_FILE=/etc/cloudwatch-alarm-exporter/aws/config
ENV AWS_SHARED_CREDENTIALS_FILE=/etc/cloudwatch-alarm-exporter/aws/credentials
ENV AWS_SDK_LOAD_CONFIG=1

EXPOSE 8080

ENTRYPOINT [ "./cloudwatch-alarm-exporter" ]
CMD        ["--port=8080", "--retries=1", "--refresh=10" ]
