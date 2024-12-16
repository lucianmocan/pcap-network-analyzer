# Use an appropriate base image
FROM gcc:latest

# Install CMake
RUN apt-get update && apt-get install -y cmake libpcap-dev

# Set environment variables
ENV BUILD_OUTPUT_DIR=/workspace/build
ENV C_COMPILER=gcc
ENV CMAKE_BUILD_TYPE=Release

# Set the working directory
WORKDIR /workspace

# Copy the entire project into the container
COPY . /workspace

# Clear any existing CMake cache and build files
RUN rm -rf ${BUILD_OUTPUT_DIR}/*

# Run CMake to configure the project
RUN cmake -B ${BUILD_OUTPUT_DIR} \
    -DCMAKE_C_COMPILER=${C_COMPILER} \
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} \
    -S .

# Build the project
RUN cmake --build ${BUILD_OUTPUT_DIR}