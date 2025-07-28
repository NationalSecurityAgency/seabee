KMOD_DIR = /lib/modules/$(shell uname -r)
KMOD_BUILD = $(KMOD_DIR)/build
INSTALL_MOD_DIR = extra
KMOD_NAME = hello_world_kmod
KMOD_COMPRESSED_NAME = $(KMOD_NAME)_compressed
KMOD_PATH = $(KMOD_DIR)/$(INSTALL_MOD_DIR)/$(KMOD_NAME).ko
KMOD_COMPRESSED = $(KMOD_DIR)/$(INSTALL_MOD_DIR)/$(KMOD_COMPRESSED_NAME).ko.xz
KMOD_COMPRESSED_TMP = $(KMOD_COMPRESSED_NAME).ko.xz

obj-m += $(KMOD_NAME).o

.PHONY: clean show test

clean:
	sudo make -C $(KMOD_BUILD) M=$$PWD clean
	sudo rm -f $(KMOD_PATH) $(KMOD_COMPRESSED)

$(KMOD_COMPRESSED): $(KMOD_PATH)
	@sudo xz -k -cf $(KMOD_PATH) > $(KMOD_COMPRESSED_TMP)
	@sudo chown root:root $(KMOD_COMPRESSED_TMP)
	@sudo mv $(KMOD_COMPRESSED_TMP) $(KMOD_COMPRESSED)
	@-sudo chcon -t modules_object_t $(KMOD_COMPRESSED)
	@sudo depmod

# If this rule fails, try rebooting
$(KMOD_PATH): $(KMOD_NAME).c
	@sudo make -C $(KMOD_BUILD) M=$$PWD modules
	@sudo make -C $(KMOD_BUILD) M=$$PWD modules_install INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)
	@sudo depmod

show:
	lsmod

test: $(KMOD_PATH) $(KMOD_COMPRESSED)
	@-sudo modprobe -rq $(KMOD_NAME)
