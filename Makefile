PWD = $(shell pwd)

all:
	CGO_ENABLED=0 go build
	docker build -t cwae .
clean:
	rm cloudwatch-alarm-exporter
	docker rmi cwae
test:
	docker run --rm -ti --expose 8080 --network host -v $(PWD)/credentials:/etc/cloudwatch-alarm-exporter/aws/credentials -v $(PWD)/config:/etc/cloudwatch-alarm-exporter/aws/config -e AWS_PROFILE=monitoring-ads-prod -e AWS_REGION=us-west-2 cwae
