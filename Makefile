all:
	cmake -S . -B build
	cd build/ && make
	cd build/ && ctest --output-on-failure
	cd build/ && cd cli/ && cp pcapna ../../
clean:
	rm -rf build/
	rm -f pcapna

docker-build:
	docker build -t pcap_analyzer_image -f .docker/Dockerfile .

docker-run:
	docker run -it pcap_analyzer_image