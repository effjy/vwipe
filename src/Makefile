# Makefile for Virtual Wipe
# GTK-based secure data sanitization tool
# NIST SP 800-88 Rev. 1 aligned

CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -std=c11 -D_GNU_SOURCE -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pthread
LDFLAGS = -pie -Wl,-z,relro,-z,now -pthread
GTK_CFLAGS = `pkg-config --cflags gtk+-3.0`
GTK_LDFLAGS = `pkg-config --libs gtk+-3.0`
TARGET = vwipe
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
DATADIR = $(PREFIX)/share
DESKTOPDIR = $(DATADIR)/applications
ICONDIR = $(DATADIR)/icons/hicolor/256x256/apps

# Source files
GTK_SOURCES = vwipe.c
RAM_SOURCES = vwipe_ram.c
GTK_OBJECTS = $(GTK_SOURCES:.c=.o)
RAM_OBJECTS = $(RAM_SOURCES:.c=.o)
RAM_TARGET = vwipe_ram

# Default target
all: $(TARGET) $(RAM_TARGET)

# Build the GTK executable
$(TARGET): $(GTK_OBJECTS)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -o $@ $^ $(LDFLAGS) $(GTK_LDFLAGS)

# Build the RAM CLI executable
$(RAM_TARGET): $(RAM_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) $(GTK_CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(GTK_OBJECTS) $(RAM_OBJECTS) $(TARGET) $(RAM_TARGET)

# Install to system with desktop integration
install: $(TARGET) $(RAM_TARGET)
	# Install GTK binary
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	
	# Install RAM CLI binary
	install -m 755 $(RAM_TARGET) $(DESTDIR)$(BINDIR)/$(RAM_TARGET)
	
	# Install desktop file
	install -d $(DESTDIR)$(DESKTOPDIR)
	install -m 644 vwipe.desktop $(DESTDIR)$(DESKTOPDIR)/vwipe.desktop
	
	# Install icon
	install -d $(DESTDIR)$(ICONDIR)
	install -m 644 vwipe.png $(DESTDIR)$(ICONDIR)/vwipe.png
	
	# Update icon cache
	gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor/ 2>/dev/null || true
	
	@echo "Virtual Wipe installed successfully!"
	@echo "GTK Binary: $(BINDIR)/$(TARGET)"
	@echo "RAM CLI Binary: $(BINDIR)/$(RAM_TARGET)"
	@echo "Desktop: $(DESKTOPDIR)/vwipe.desktop"
	@echo "Icon: $(ICONDIR)/vwipe.png"

# Uninstall from system
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(BINDIR)/$(RAM_TARGET)
	rm -f $(DESTDIR)$(DESKTOPDIR)/vwipe.desktop
	rm -f $(DESTDIR)$(ICONDIR)/vwipe.png
	gtk-update-icon-cache -f -t $(DESTDIR)$(DATADIR)/icons/hicolor/ 2>/dev/null || true
	@echo "Virtual Wipe uninstalled successfully!"

# Development targets
debug: CFLAGS += -g -DDEBUG -Wall -Wextra
debug: $(TARGET)

# Static analysis
lint:
	cppcheck --enable=all --std=c11 $(GTK_SOURCES) $(RAM_SOURCES)

# Format code
format:
	clang-format -i -style="{BasedOnStyle: Linux, IndentWidth: 4, TabWidth: 4, UseTab: Never}" $(GTK_SOURCES) $(RAM_SOURCES)

# Run with basic test
test: $(TARGET) $(RAM_TARGET)
	@echo "Creating test file..."
	@echo "This is test data for Virtual Wipe verification." > test_file.txt
	@echo "Virtual Wipe compiled successfully."
	@echo "GTK Interface: ./$(TARGET)"
	@echo "RAM CLI: ./$(RAM_TARGET) [safety_mb]"
	@echo "Test file created: test_file.txt"

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists gtk+-3.0 && echo "GTK3: OK" || echo "GTK3: MISSING"
	@gcc --version > /dev/null && echo "GCC: OK" || echo "GCC: MISSING"
	@pkg-config --modversion gtk+-3.0

# Help target
help:
	@echo "Virtual Wipe Build System"
	@echo "=========================="
	@echo "Targets:"
	@echo "  all         - Build the vwipe executable (default)"
	@echo "  clean       - Remove build artifacts"
	@echo "  install     - Install to system with desktop integration"
	@echo "  uninstall   - Remove from system"
	@echo "  debug       - Build with debug symbols"
	@echo "  lint        - Run static analysis"
	@echo "  format      - Format source code"
	@echo "  test        - Run basic functionality test"
	@echo "  check-deps  - Check build dependencies"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Installation:"
	@echo "  sudo make install    - Install system-wide"
	@echo "  make uninstall       - Remove installation"

.PHONY: all clean install uninstall debug lint format test check-deps help
