TARGET = file_crypto
SRCS = main.cpp

CXX = g++
CXXFLAGS = -std=c++11 -Wall
OPENSSL_FLAGS = $(shell pkg-config --cflags --libs openssl)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(OPENSSL_FLAGS)

clean:
	rm -f $(TARGET)
