all: container push

build-pause-c:
	mkdir -p bin
	gcc -static -O3 pause.c -o bin/pause

container:
	mkdir -p bin
	cp ../../bin/pause bin/
	docker build -t gui774ume/pause2:latest -t gui774ume/pause2:3.2 --squash .

login:
	docker login --username gui774ume

push:
	docker push gui774ume/pause2:latest
	docker push gui774ume/pause2:3.2
