all:
	cmake -S . -B build
	cd build/ && make
	cd build/ && ctest --output-on-failure

clean:
	rm -rf build/