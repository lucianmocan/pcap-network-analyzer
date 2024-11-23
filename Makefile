all:
	cmake -S . -B build
	cd build/ && make
	cd build/ && ctest

clean:
	rm -rf build/