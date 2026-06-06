
include $(RULESDIR)/common.mk

$(CORE_OBJECTS) $(TCPIP_OBJECTS): CFLAGS   += -fPIC
$(CORE_OBJECTS) $(TCPIP_OBJECTS): CXXFLAGS += -fPIC
ifdef ENABLESEC
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CFLAGS   += -fPIC
$(FUZZ_OBJECTS) $(SECURITY_OBJECTS): CXXFLAGS += -fPIC
# libxml2 include path via pkg-config (with guarded fallback), see common.mk.
$(SECURITY_OBJECTS): CFLAGS += $(LIBXML2_CFLAGS)
$(FUZZ_OBJECTS): CFLAGS += $(LIBXML2_CFLAGS)
endif

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#  R E L E A S E   O P T I M I Z A T I O N   &   H A R D E N I N G   ( B1, B2 )
#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Applied only to optimized release builds (the default -O3 path) on Linux.
# Skipped for DEBUG, VALGRIND and BUILD=asan so they do not perturb debugging,
# Valgrind traces or the sanitizer runtime.
#
# B1 - link-time optimization + dead-section GC:
#   -flto=auto                optimizes across translation units (GCC spelling).
#   -ffunction-sections
#   -fdata-sections           emit each function/datum in its own section so the
#   -Wl,--gc-sections         linker can drop everything unreferenced, shrinking
#                             the shared objects.
#   -fno-semantic-interposition  lets the compiler inline/clone within the .so
#                             instead of routing every call through the PLT.
#
# B2 - exploit hardening:
#   -D_FORTIFY_SOURCE=2       run-time bounds checks on libc str/mem calls
#                             (requires optimization; already -O3). Undefined
#                             first so an explicit =2 never collides with a
#                             toolchain that pre-defines it (Ubuntu's GCC default
#                             is 3) and emits a "redefined" warning.
#   -fstack-protector-strong
#   -fstack-clash-protection  stack smashing / stack-clash hardening.
#   -Wl,-z,relro -Wl,-z,now   full RELRO: GOT resolved at load then made
#                             read-only (BIND_NOW).
#   -Wl,-z,noexecstack        mark the stack non-executable.
#
# This is a DISTRIBUTED shared library, so deliberately NO -march=native /
# -mtune=native here - those would emit instructions that SIGILL on older
# baseline CPUs.
#
# -flto=auto is GCC-only (Clang rejects the "auto" argument), so LTO is enabled
# for GCC alone; the remaining flags are accepted by both GCC and Clang. icc is
# excluded from the whole block.

MMT_RELEASE_BUILD := 1
ifdef DEBUG
MMT_RELEASE_BUILD :=
endif
ifdef VALGRIND
MMT_RELEASE_BUILD :=
endif
ifeq ($(BUILD),asan)
MMT_RELEASE_BUILD :=
endif

ifeq ($(MMT_RELEASE_BUILD),1)
ifneq (,$(filter gcc clang,$(CC)))

# Compile-time flags - applied to every C and C++ object.
MMT_HARDEN_CFLAGS := \
    -ffunction-sections -fdata-sections -fno-semantic-interposition \
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong -fstack-clash-protection

# Link-time flags. The .so recipes in this file link with $(CXXFLAGS) - the same
# convention the BUILD=asan path relies on - so these are appended to CXXFLAGS
# (below) to reach every shared-library link line without editing each recipe.
MMT_HARDEN_LDFLAGS := \
    -Wl,--gc-sections \
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# LTO must be present at BOTH compile and link; -flto=auto is GCC-only.
ifneq (,$(filter gcc,$(CC)))
MMT_HARDEN_CFLAGS  += -flto=auto
MMT_HARDEN_LDFLAGS += -flto=auto
endif

CFLAGS   += $(MMT_HARDEN_CFLAGS)
CXXFLAGS += $(MMT_HARDEN_CFLAGS) $(MMT_HARDEN_LDFLAGS)

endif   # gcc/clang only
endif   # release builds only

#  - - - - - - - - - - - - - - -
#  L I N U X   L I B R A R I E S
#  - - - - - - - - - - - - - - -

#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#  P E R - L I B R A R Y   L I N K   F L A G S   ( B3, B4 )
#  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Link libraries now live on the link line (the .so recipes append $(LDLIBS),
# and $(LDFLAGS) for linker options). $(LDLIBS) defaults to -lm (common.mk);
# the protocol libs that historically declared nghttp2, and the ENABLESEC
# engines that use libxml2, add theirs here.
$(SDKLIB)/$(LIBTCPIP).so.$(VERSION):  LDLIBS += $(NGHTTP2_LIBS)
$(SDKLIB)/$(LIBMOBILE).so.$(VERSION): LDLIBS += $(NGHTTP2_LIBS)
# libmmt_core dlopen()s the protocol plugins; keep -ldl explicit so the link is
# self-contained under -Wl,-z,defs even on toolchains that split libdl out of
# libc.
$(SDKLIB)/$(LIBCORE).so.$(VERSION):   LDLIBS += -ldl

# -Wl,-z,defs (a.k.a. --no-undefined) makes the linker fail on any unresolved
# symbol. Only libmmt_core is fully self-contained: the protocol plugins
# (tcpip, tmobile, business_app, tdicom) and the ENABLESEC engines deliberately
# leave core symbols (mmt_malloc, register_protocol, ...) undefined and resolve
# them at load time when the MMT framework dlopen()s them into one address
# space, so they cannot satisfy --no-undefined. BUILD=asan also leaves the
# ASan/UBSan runtime symbols undefined by design (resolved via LD_PRELOAD, see
# common.mk), so the guard is skipped for the sanitizer profile.
ifneq ($(BUILD),asan)
$(SDKLIB)/$(LIBCORE).so.$(VERSION):    LDFLAGS += -Wl,-z,defs
endif
ifdef ENABLESEC
$(SDKLIB)/$(LIBSECURITY).so.$(VERSION): LDLIBS += $(LIBXML2_LIBS)
$(SDKLIB)/$(LIBFUZZ).so.$(VERSION):     LDLIBS += $(LIBXML2_LIBS)
endif

libraries: \
	$(SDKLIB)/$(LIBCORE).so \
	$(SDKLIB)/$(LIBTCPIP).so \
	$(SDKLIB)/$(LIBMOBILE).so \
	$(SDKLIB)/$(LIBBAPP).so \
	$(SDKLIB)/$(LIBDICOM).so
ifdef ENABLESEC
libraries: \
	$(SDKLIB)/$(LIBFUZZ).so \
	$(SDKLIB)/$(LIBSECURITY).so
endif
# CORE

$(SDKLIB)/$(LIBCORE).so: $(SDKLIB)/$(LIBCORE).so.$(VERSION)

$(SDKLIB)/$(LIBCORE).so.$(VERSION): $(SDKLIB)/$(LIBCORE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBCORE).so $(LDLIBS)

# TCP/IP

$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)

$(SDKLIB)/$(LIBTCPIP).so.$(VERSION): $(SDKLIB)/$(LIBTCPIP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBTCPIP).so $(LDLIBS)

$(SDKLIB)/$(LIBTCPIP).so: $(SDKLIB)/$(LIBTCPIP).so.$(VERSION)

# LIB_MOBILE 4G 5G
$(SDKLIB)/$(LIBMOBILE).so: $(SDKLIB)/$(LIBMOBILE).so.$(VERSION)

$(SDKLIB)/$(LIBMOBILE).so.$(VERSION): $(SDKLIB)/$(LIBMOBILE).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBMOBILE).so $(LDLIBS)

# BUSINESS APP/PROTOCOLS
$(SDKLIB)/$(LIBBAPP).so: $(SDKLIB)/$(LIBBAPP).so.$(VERSION)

$(SDKLIB)/$(LIBBAPP).so.$(VERSION): $(SDKLIB)/$(LIBBAPP).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBBAPP).so $(LDLIBS)

ifdef ENABLESEC
# FUZZ

$(SDKLIB)/$(LIBFUZZ).so: $(SDKLIB)/$(LIBFUZZ).so.$(VERSION)

$(SDKLIB)/$(LIBFUZZ).so.$(VERSION): $(SDKLIB)/$(LIBFUZZ).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBFUZZ).so $(LDLIBS)

# SECURITY

$(SDKLIB)/$(LIBSECURITY).so: $(SDKLIB)/$(LIBSECURITY).so.$(VERSION)

$(SDKLIB)/$(LIBSECURITY).so.$(VERSION): $(SDKLIB)/$(LIBSECURITY).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBSECURITY).so $(LDLIBS)
endif

# DICOM
$(SDKLIB)/$(LIBDICOM).so: $(SDKLIB)/$(LIBDICOM).so.$(VERSION)

$(SDKLIB)/$(LIBDICOM).so.$(VERSION): $(SDKLIB)/$(LIBDICOM).a
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CXX) $(CXXFLAGS) $(LDFLAGS) -shared -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive -Wl,--soname=$(LIBDICOM).so $(LDLIBS)
