COMMON_FLAGS := -m64 -O3

COMMON_CFLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow -Wno-format-security\
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls -Wnon-virtual-dtor

SRCS := src/App.cpp src/ecdh.cpp src/shamir.cpp src/aes.cpp src/mask.cpp

App_Include_Paths := -I./include -lcryptopp

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths) -DNDEBUG

App_Cpp_Flags := -std=c++11 $(App_C_Flags) -mavx2 -mfma
App_Link_Flags := -lcryptopp

OBJS := $(SRCS:.cpp=.o)

App_Name := app

all: $(App_Name)

src/%.o: src/%.cpp 
	@$(CXX) $(COMMON_CFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(OBJS)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(OBJS)
