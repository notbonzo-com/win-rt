ifeq ($(OS),Windows_NT)
    CLEAR         = cls
    MKDIR         = mkdir
    RM_DIR        = rmdir /S /Q
    RM_FILE       = del /Q

    C_SRCS        := $(shell dir /S /B runtime\*.c tests\*.c 2>NUL)
    ASM_SRCS      := $(shell dir /S /B runtime\*.asm tests\*.asm 2>NUL)
    HASHREC_SRCS  := $(shell dir /S /B runtime\*.hashrec tests\*.hashrec 2>NUL)

    BUILD_SUBDIRS = $(BUILD_DIR)

    run:
	    @echo "------------"
	    @$(OUT)
	    @echo "------------"

else
    CLEAR         = clear
    MKDIR         = mkdir -p
    RM            = rm -rf
	
    C_SRCS        = $(shell find $(SRC_DIRS) -type f -name "*.c")
    ASM_SRCS      = $(shell find $(SRC_DIRS) -type f -name "*.asm")
    HASHREC_SRCS  = $(shell find $(SRC_DIRS) -type f -name "*.hashrec")

    BUILD_SUBDIRS = $(shell find $(SRC_DIRS) -type d | sed 's|^|$(BUILD_DIR)/|')

    run:
	    @echo "------------"
	    @wine $(OUT)
	    @echo "------------"
endif

CC       = clang-cl
ASM      = nasm
LD       = lld-link

TARGET   = x86_64-w64-mingw32
ARCH     = x86_64

SRC_DIRS = runtime tests
BUILD_DIR = $(abspath build)
OUT      = program.exe

CFLAGS   = /D_CRT_SECURE_NO_WARNINGS /nologo /c /GS- /W3 /Oi /O2 /Zc:inline /Zc:forScope /FC /EHa /GR- /clang:-std=c23 /I runtime
ASMFLAGS = -f win64

LDFLAGS  = /SUBSYSTEM:CONSOLE \
           /ENTRY:_start \
           /BASE:0x400000 \
           /NODEFAULTLIB \
           /NOLOGO

OBJS = $(patsubst %,$(BUILD_DIR)/%,$(C_SRCS:.c=.obj)) \
       $(patsubst %,$(BUILD_DIR)/%,$(ASM_SRCS:.asm=.obj))

HASHREC_HEADERS = $(patsubst %.hashrec,%.h,$(HASHREC_SRCS))

all: $(BUILD_DIR) $(HASHREC_HEADERS) $(OUT) run
	@echo "✅ Build complete: $(OUT)"

$(BUILD_DIR):
	@echo "📂 Creating build directories..."
	@$(MKDIR) $(BUILD_SUBDIRS)

%.h: %.hashrec parse_hashrec.py
	@echo "📜 Parsing $< -> $@"
	@python3 parse_hashrec.py $< $@
$(BUILD_DIR)/%.obj: %.c | $(BUILD_DIR)
	@echo "🔨 Compiling C: $<"
	@$(MKDIR) $(dir $@)
	@$(CC) $(CFLAGS) /Fo$@ $<
	@$(LOG_CC)

$(BUILD_DIR)/%.obj: %.asm | $(BUILD_DIR)
	@echo "🛠️  Assembling: $<"
	@$(MKDIR) $(dir $@)
	@$(ASM) $(ASMFLAGS) -o $@ $<

$(OUT): $(OBJS)
	@echo "🔗 Linking with LLD: $(OUT)"
	@$(LD) $(LDFLAGS) /OUT:$@ $^

clean:
	@$(CLEAR)
	@echo "🧹 Cleaning up..."
ifeq ($(OS),Windows_NT)
	@$(RM_DIR) $(BUILD_DIR)
	@$(RM_FILE) $(OUT) $(HASHREC_HEADERS)
else
	@$(RM) $(BUILD_DIR) $(OUT) $(HASHREC_HEADERS)
endif

reset: clean all

.PHONY: all clean reset run
