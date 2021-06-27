all: container push

container:
	mkdir -p bin
	cp ../../bin/webapp bin/
	docker build -t gui774ume/webapp:latest --squash .

login:
	docker login --username gui774ume

push:
	docker push gui774ume/webapp:latest
