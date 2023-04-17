CC = nvcc
CFLAGS = -O3 -std=c++17
DEPS = blake3.hpp cuda-raii.hpp pony.hpp
OBJ = blake3.o main.o pony.o

%.o: %.cu $(DEPS)
	$(CC) -dc -o $@ $< $(CFLAGS)

main: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)