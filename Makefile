LOG_CC = test -f compile_commands.json || echo '[' > compile_commands.json; \
         echo '{ "directory": "$(shell pwd)", "command": "$(CC) $(CFLAGS) -c $< -o $@", "file": "$<" },' >> compile_commands.json

CC = clang-cl
ASM = nasm

TARGET = x86_64-w64-mingw32
ARCH = x86_64

LD = lld-link

SRC_DIRS = runtime tests
BUILD_DIR = $(abspath build)
OUT = program.exe

CFLAGS = /D_CRT_SECURE_NO_WARNINGS /nologo /c /GS- /W3 /Oi /O2 /Zc:inline /Zc:forScope /FC /EHa /GR- /clang:-std=c23 /I runtime
ASMFLAGS = -f win64

LDFLAGS = /SUBSYSTEM:CONSOLE \
          /ENTRY:_start \
          /BASE:0x400000 \
          /NODEFAULTLIB \
          /NOLOGO

C_SRCS = $(shell find $(SRC_DIRS) -type f -name "*.c")
ASM_SRCS = $(shell find $(SRC_DIRS) -type f -name "*.asm")
HASHREC_SRCS = $(shell find $(SRC_DIRS) -type f -name "*.hashrec")

OBJS = $(patsubst %,$(BUILD_DIR)/%,$(C_SRCS:.c=.obj)) \
       $(patsubst %,$(BUILD_DIR)/%,$(ASM_SRCS:.asm=.obj))

HASHREC_HEADERS = $(patsubst %.hashrec,%.h,$(HASHREC_SRCS))

BUILD_SUBDIRS = $(shell find $(SRC_DIRS) -type d | sed 's|^|$(BUILD_DIR)/|')

all: $(BUILD_DIR) $(HASHREC_HEADERS) $(OUT) fix_compile_commands run
	@echo "✅ Build complete: $(OUT)"

$(BUILD_DIR):
	@echo "📂 Creating build directories..."
	@mkdir -p $(BUILD_SUBDIRS)

%.h: %.hashrec parse_hashrec.py
	@echo "📜 Parsing $< -> $@"
	@python3 parse_hashrec.py $< $@

$(BUILD_DIR)/%.obj: %.c | $(BUILD_DIR)
	@echo "🔨 Compiling C: $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) /Fo$@ $<
	@$(LOG_CC)

$(BUILD_DIR)/%.obj: %.asm | $(BUILD_DIR)
	@echo "🛠️  Assembling: $<"
	@mkdir -p $(dir $@)
	@$(ASM) $(ASMFLAGS) -o $@ $<

$(OUT): $(OBJS)
	@echo "🔗 Linking with LLD: $(OUT)"
	@$(LD) $(LDFLAGS) /OUT:$@ $^

fix_compile_commands:
	@echo "🔧 Fixing compile_commands.json formatting..."
	@sed -i '$$ s/,$$//' compile_commands.json
	@echo "]" >> compile_commands.json

clean:
	@clear
	@echo "🧹 Cleaning up..."
	@rm -rf $(BUILD_DIR) $(OUT) $(HASHREC_HEADERS) compile_commands.json

reset: clean all

run:
	@echo "------------"
	@wine $(OUT)
	@echo "------------"

objdump:
	@x86_64-w64-mingw32-objdump -x $(OUT)

.PHONY: all clean objdump reset run fix_compile_commands