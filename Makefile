# -------------------------------
# Cross-platform Makefile
# ------------------------------
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -I./src
LDFLAGS = 
TARGET = chacha20_test.exe
LIBRARY = libchacha20.a

# Source files
SRC_DIR = src
SRCS = $(SRC_DIR)/chacha20_poly1305_core.c $(SRC_DIR)/test_app.c
OBJS = $(SRCS:.c=.o)

# Platform detection and specific flags
ifeq ($(OS),Windows_NT)
    # Windows specific
    CFLAGS += -DPLATFORM_WINDOWS -D_CRT_SECURE_NO_WARNINGS
    LDFLAGS += -ladvapi32
    MKDIR = if not exist
    RMDIR = rmdir /Q
    RMFILE = del /Q
    COPY = copy
    NULL_OUT = >nul
    PATHSEP = \\
else
    # Unix-like systems
    CFLAGS += -DPLATFORM_POSIX
    MKDIR = mkdir -p
    RMDIR = rm -rf
    RMFILE = rm -f
    COPY = cp
    NULL_OUT = > /dev/null
    PATHSEP = /
endif

all: $(TARGET) $(LIBRARY)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(LIBRARY): $(SRC_DIR)/chacha20_poly1305_core.o
	ar rcs $@ $^

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

static: $(LIBRARY)

clean:
	@echo "Cleaning build files..."
	@$(RMFILE) $(OBJS) $(TARGET) $(LIBRARY) $(NULL_OUT) 2>&1 || true
	@echo "Clean complete."

install: $(LIBRARY)
	@echo "Installing library..."
	@$(MKDIR) include $(NULL_OUT) 2>&1 || true
	@$(MKDIR) lib $(NULL_OUT) 2>&1 || true
	@$(COPY) $(SRC_DIR)$(PATHSEP)chacha20_poly1305_core.h include$(PATHSEP) $(NULL_OUT)
	@$(COPY) $(LIBRARY) lib$(PATHSEP) $(NULL_OUT)
	@echo "Library installed to include/ and lib/ directories."

test: $(TARGET)
	@echo "Running tests..."
	@./$(TARGET)

.PHONY: all clean install test static